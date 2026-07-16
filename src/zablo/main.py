"""
Zablo CLI entrypoint.

Commands:
  zablo configure                                    Interactive one-time setup
  zablo put <path>                                   Read plaintext from stdin, encrypt, upload
  zablo get <path>                                   Fetch, decrypt, print to stdout
  zablo ls [prefix]                                  List secrets
  zablo rm <path>                                    Crypto-shred a secret
  zablo exec --env NAME=path -- <cmd> [args...]      Inject secrets as env, exec child
  zablo verify <path>                                Print lineage chain metadata
  zablo federate --token <jwt> [--audience]          Exchange upstream OIDC JWT for a session
  zablo whoami                                       Show current auth context
  zablo version
"""

from __future__ import annotations

import getpass
import os
import subprocess
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from zablo import __version__
from zablo.client import ApiError, Client
from zablo.config import DEFAULT_URL, Profile, save_profile
from zablo.crypto import EncryptedPayload, decrypt, encrypt, wipe_string

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
    rich_markup_mode=None,
)
err = Console(stderr=True)
out = Console()


def _fail(msg: str, code: int = 1) -> None:
    err.print(f"[red]zablo:[/red] {msg}")
    raise typer.Exit(code=code)


def _client(profile: str) -> Client:
    p = Profile.load(profile)
    return Client(p.api_url, api_key=p.require_key())


# ---------------------------------------------------------------------------
# configure
# ---------------------------------------------------------------------------

@app.command()
def configure(
    profile: str = typer.Option("default", "--profile", "-p", help="Profile name"),
) -> None:
    """One-time setup. Persists to ~/.zablo/config.toml."""
    current = Profile.load(profile)
    out.print(f"[bold]Zablo profile:[/bold] {profile}")
    api_url = typer.prompt("API URL", default=current.api_url or DEFAULT_URL)
    api_key = typer.prompt("API key (starts with vk_)", default=current.api_key or "", hide_input=True, show_default=False)
    passphrase = typer.prompt(
        "Client passphrase (never sent to the server)",
        default=current.passphrase or "",
        hide_input=True,
        show_default=False,
    )
    path = save_profile(profile, api_url, api_key or None, passphrase or None)
    out.print(f"[green]Saved[/green] {path} (perms 0600)")


# ---------------------------------------------------------------------------
# put
# ---------------------------------------------------------------------------

@app.command()
def put(
    path: str = typer.Argument(..., help="Secret path, e.g. prod/db/password"),
    kind: str = typer.Option("standard", "--kind", help="standard | canary | ephemeral"),
    profile: str = typer.Option("default", "--profile", "-p"),
) -> None:
    """Read plaintext from stdin, encrypt client-side, upload."""
    if sys.stdin.isatty():
        _fail("no input on stdin. Try:  echo -n 'value' | zablo put " + path)
    plaintext = sys.stdin.read().rstrip("\n")
    if not plaintext:
        _fail("stdin was empty")

    p = Profile.load(profile)
    passphrase = p.require_passphrase()
    payload = encrypt(plaintext, passphrase)
    wipe_string(plaintext)

    with Client(p.api_url, api_key=p.require_key()) as c:
        try:
            resp = c.put_secret(
                path=path,
                ciphertext_b64=payload.ciphertext,
                client_iv_b64=payload.iv,
                client_salt_b64=payload.salt,
                kind=kind,
                envelope_version=payload.version,
            )
        except ApiError as e:
            _fail(str(e))

    out.print(f"[green]✓[/green] stored [bold]{path}[/bold]  ({kind})")
    lineage = resp.get("lineageHash", "")
    if lineage:
        out.print(f"  lineage: [dim]{lineage[:16]}…[/dim]")


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------

@app.command()
def get(
    path: str = typer.Argument(...),
    profile: str = typer.Option("default", "--profile", "-p"),
) -> None:
    """Fetch a secret, decrypt client-side, print to stdout."""
    p = Profile.load(profile)
    passphrase = p.require_passphrase()

    with Client(p.api_url, api_key=p.require_key()) as c:
        try:
            row = c.get_secret(path)
        except ApiError as e:
            if e.status == 404:
                _fail(f"secret not found: {path}")
            _fail(str(e))

    payload = EncryptedPayload(
        ciphertext=row["ciphertext"],
        iv=row["clientIv"],
        salt=row["clientSalt"],
        version=int(row.get("envelopeVersion", 1)),
    )
    try:
        plain = decrypt(payload, passphrase)
    except Exception:  # noqa: BLE001
        _fail("decryption failed — wrong passphrase?")
    sys.stdout.write(plain)
    if sys.stdout.isatty():
        sys.stdout.write("\n")


# ---------------------------------------------------------------------------
# ls
# ---------------------------------------------------------------------------

@app.command("ls")
def list_(
    prefix: Optional[str] = typer.Argument(None),
    profile: str = typer.Option("default", "--profile", "-p"),
) -> None:
    """List secret paths, optionally filtered by prefix."""
    p = Profile.load(profile)
    with Client(p.api_url, api_key=p.require_key()) as c:
        try:
            rows = c.list_secrets(prefix)
        except ApiError as e:
            _fail(str(e))
    if not rows:
        err.print("[dim]no secrets found[/dim]")
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("Kind", style="dim")
    table.add_column("Path")
    table.add_column("Created", style="dim")
    for r in rows:
        table.add_row(r.get("kind", "standard"), r.get("path", ""), r.get("createdAt", ""))
    out.print(table)


# ---------------------------------------------------------------------------
# rm
# ---------------------------------------------------------------------------

@app.command("rm")
def remove(
    path: str = typer.Argument(...),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
    profile: str = typer.Option("default", "--profile", "-p"),
) -> None:
    """Crypto-shred a secret. Not reversible."""
    if not yes:
        if not typer.confirm(f"Shred {path}? This is not reversible."):
            raise typer.Exit(1)
    p = Profile.load(profile)
    with Client(p.api_url, api_key=p.require_key()) as c:
        try:
            c.delete_secret(path)
        except ApiError as e:
            if e.status == 404:
                _fail(f"not found: {path}")
            _fail(str(e))
    err.print(f"[yellow]shredded[/yellow] {path}")


# ---------------------------------------------------------------------------
# exec — sidecar
# ---------------------------------------------------------------------------

@app.command("exec")
def exec_(
    ctx: typer.Context,
    env: list[str] = typer.Option(
        [],
        "--env",
        help="NAME=path — fetch secret at `path` and inject as env var NAME. Repeatable.",
    ),
    profile: str = typer.Option("default", "--profile", "-p"),
) -> None:
    """
    Fetch secrets, inject into child process env, exec.
    Plaintext never touches disk.

    Example:
      zablo exec --env DB_PASSWORD=prod/db/password -- ./deploy.sh
    """
    # Split argv after `--`
    argv = ctx.args
    if "--" in argv:
        idx = argv.index("--")
        cmd_and_args = argv[idx + 1 :]
    else:
        cmd_and_args = argv
    if not cmd_and_args:
        _fail("exec: expected `-- <cmd> [args...]`")

    injections: list[tuple[str, str]] = []
    for spec in env:
        if "=" not in spec:
            _fail(f"exec: invalid --env spec '{spec}' (expected NAME=path)")
        name, path = spec.split("=", 1)
        injections.append((name.strip(), path.strip()))

    p = Profile.load(profile)
    passphrase = p.require_passphrase()

    child_env = os.environ.copy()
    with Client(p.api_url, api_key=p.require_key()) as c:
        for name, path in injections:
            try:
                row = c.get_secret(path)
            except ApiError as e:
                _fail(f"exec: failed to fetch {path}: {e}")
            payload = EncryptedPayload(
                ciphertext=row["ciphertext"],
                iv=row["clientIv"],
                salt=row["clientSalt"],
                version=int(row.get("envelopeVersion", 1)),
            )
            try:
                child_env[name] = decrypt(payload, passphrase)
            except Exception:  # noqa: BLE001
                _fail(f"exec: decryption failed for {path} — wrong passphrase?")

    # Execute child. On success we replace ourselves (execvpe) so signals
    # forward correctly. Falls back to subprocess on Windows.
    try:
        os.execvpe(cmd_and_args[0], cmd_and_args, child_env)  # noqa: S606
    except OSError as e:
        _fail(f"exec: {e}")


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

@app.command()
def verify(
    path: str = typer.Argument(...),
    profile: str = typer.Option("default", "--profile", "-p"),
) -> None:
    """Print the current lineage hash + parent for a secret."""
    p = Profile.load(profile)
    with Client(p.api_url, api_key=p.require_key()) as c:
        try:
            row = c.get_secret(path)
        except ApiError as e:
            _fail(str(e))
    out.print(f"[bold]path:[/bold]     {row.get('path')}")
    out.print(f"[bold]lineage:[/bold]  {row.get('lineageHash')}")
    parent = row.get("parentSecretId")
    out.print(f"[bold]parent:[/bold]   {parent or '(root of chain)'}")


# ---------------------------------------------------------------------------
# federate — OIDC token exchange
# ---------------------------------------------------------------------------

@app.command()
def federate(
    subject_token: Optional[str] = typer.Option(
        None,
        "--subject-token",
        "-t",
        help="Upstream IdP JWT. If omitted, read from stdin.",
    ),
    audience: str = typer.Option("zablo.io", "--audience"),
    api_url: Optional[str] = typer.Option(None, "--url", help="Override API URL"),
    export: bool = typer.Option(
        False, "--export", help="Print `export ZABLO_API_KEY=...` for eval"
    ),
) -> None:
    """
    Exchange an upstream OIDC JWT for a short-lived Zablo session token.

    Perfect for GitHub Actions, Kubernetes projected SA, etc. Example:

      TOKEN=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \\
              "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=zablo.io" | jq -r .value)
      eval "$(zablo federate --subject-token $TOKEN --export)"
    """
    if not subject_token:
        if sys.stdin.isatty():
            _fail("federate: no --subject-token given and stdin is empty")
        subject_token = sys.stdin.read().strip()

    url = api_url or Profile.load("default").api_url
    # Federation endpoint is public -- no bearer needed
    client = Client(url, api_key=None)
    try:
        resp = client.federate(subject_token, audience=audience)
    except ApiError as e:
        _fail(str(e))
    finally:
        client.close()

    if export:
        sys.stdout.write(f'export ZABLO_API_KEY="{resp["access_token"]}"\n')
        return
    out.print(f"[bold]access_token:[/bold] {resp['access_token']}")
    out.print(f"[bold]expires_in:[/bold]   {resp.get('expires_in', '?')} s")
    out.print(f"[bold]machine_user:[/bold] {resp.get('machine_user', '?')}")


# ---------------------------------------------------------------------------
# whoami / version
# ---------------------------------------------------------------------------

@app.command()
def whoami(
    profile: str = typer.Option("default", "--profile", "-p"),
) -> None:
    """Show which profile is active and where it's pointed."""
    p = Profile.load(profile)
    out.print(f"[bold]profile:[/bold]     {profile}")
    out.print(f"[bold]api_url:[/bold]     {p.api_url}")
    if p.api_key:
        out.print(f"[bold]api_key:[/bold]     {p.api_key[:11]}… ([dim]set[/dim])")
    else:
        out.print("[bold]api_key:[/bold]     [red](not set)[/red]")
    out.print(f"[bold]passphrase:[/bold]  {'set' if p.passphrase else '[red](not set)[/red]'}")
    out.print(f"[bold]user:[/bold]        {getpass.getuser()}")


@app.command()
def version() -> None:
    """Print the CLI version."""
    out.print(__version__)


# ---------------------------------------------------------------------------
# --- helpers so `exec` can consume unknown args ---
# ---------------------------------------------------------------------------
# Typer normally rejects unknown arguments; the exec subcommand needs to pass
# them through to the child process. We enable it via the CommandContext.
def _apply_exec_context_settings() -> None:
    exec_cmd = next(c for c in app.registered_commands if c.name == "exec")
    exec_cmd.context_settings = {
        "allow_extra_args": True,
        "ignore_unknown_options": True,
    }


_apply_exec_context_settings()


if __name__ == "__main__":
    _ = subprocess  # keep import for future use
    app()
