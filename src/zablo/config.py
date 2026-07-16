"""
Config resolution.

Precedence (highest wins):
  1. Explicit CLI flags (--url, --key, --passphrase)
  2. Environment variables (ZABLO_API_URL, ZABLO_API_KEY, ZABLO_PASSPHRASE)
  3. Profile file at ~/.zablo/config.toml
  4. Defaults
"""

from __future__ import annotations

import os
import stat
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import tomli_w  # type: ignore[import-untyped]
except ImportError:  # tomli_w is only needed for writing
    tomli_w = None  # type: ignore[assignment]

CONFIG_DIR = Path.home() / ".zablo"
CONFIG_FILE = CONFIG_DIR / "config.toml"
DEFAULT_URL = "https://api.zablo.io"


@dataclass
class Profile:
    api_url: str = DEFAULT_URL
    api_key: Optional[str] = None
    passphrase: Optional[str] = None  # may be pulled at runtime via keyring in future

    @classmethod
    def load(cls, profile: str = "default") -> "Profile":
        # Env vars first -- overrides everything
        env_url = os.environ.get("ZABLO_API_URL")
        env_key = os.environ.get("ZABLO_API_KEY")
        env_pass = os.environ.get("ZABLO_PASSPHRASE")

        # File
        file_data: dict[str, dict[str, str]] = {}
        if CONFIG_FILE.exists():
            with CONFIG_FILE.open("rb") as f:
                file_data = tomllib.load(f).get("profile", {})  # type: ignore[assignment]

        p = file_data.get(profile, {})
        return cls(
            api_url=env_url or p.get("api_url") or DEFAULT_URL,
            api_key=env_key or p.get("api_key"),
            passphrase=env_pass or p.get("passphrase"),
        )

    def require_key(self) -> str:
        if not self.api_key:
            sys.exit(
                "zablo: no API key configured.\n"
                "  Set ZABLO_API_KEY, or run: zablo configure"
            )
        return self.api_key

    def require_passphrase(self) -> str:
        if not self.passphrase:
            sys.exit(
                "zablo: no client passphrase configured.\n"
                "  Set ZABLO_PASSPHRASE, or run: zablo configure"
            )
        return self.passphrase


def save_profile(
    profile: str,
    api_url: str,
    api_key: Optional[str],
    passphrase: Optional[str],
) -> Path:
    """Persist a profile to ~/.zablo/config.toml with 0600 perms."""
    if tomli_w is None:
        raise RuntimeError(
            "writing config requires `tomli_w`. Install with: pip install tomli_w"
        )
    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    existing: dict[str, dict[str, dict[str, str]]] = {"profile": {}}
    if CONFIG_FILE.exists():
        with CONFIG_FILE.open("rb") as f:
            existing = tomllib.load(f) or {"profile": {}}  # type: ignore[assignment]
    existing.setdefault("profile", {})
    entry: dict[str, str] = {"api_url": api_url}
    if api_key:
        entry["api_key"] = api_key
    if passphrase:
        entry["passphrase"] = passphrase
    existing["profile"][profile] = entry

    tmp = CONFIG_FILE.with_suffix(".toml.tmp")
    with tmp.open("wb") as f:
        f.write(tomli_w.dumps(existing).encode("utf-8"))
    tmp.replace(CONFIG_FILE)
    os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)
    return CONFIG_FILE
