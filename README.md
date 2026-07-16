# Zablo CLI

[![PyPI](https://img.shields.io/pypi/v/zablo.svg)](https://pypi.org/project/zablo-cli/)
[![Python](https://img.shields.io/pypi/pyversions/zablo-cli.svg)](https://pypi.org/project/zablo-cli/)
[![License](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)

Command-line client for [**Zablo**](https://zablo.io) — zero-knowledge secrets for machines.

The server never sees your plaintext. Encryption happens on the client with your passphrase; only the ciphertext leaves the process.

> **Requires a running Zablo server.** Point the CLI at your instance with `ZABLO_API_URL` or `zablo configure`.

## Install

```sh
pip install zablo
```

Requires Python 3.9+. Installs two executables: `zablo` (canonical) and `zx` (short alias).

## Quick start

```sh
# One-time setup
zablo configure

# Write / read a secret
echo -n "super-secret-42" | zablo put prod/db/password
zablo get prod/db/password

# List, delete
zablo ls prod/
zablo rm prod/db/password

# Sidecar: inject secrets into a subprocess. Plaintext never touches disk.
zablo exec --env DB_PASSWORD=prod/db/password -- ./run-migrations.sh

# Verify cryptographic lineage of a secret (Merkle-chained rotations)
zablo verify prod/db/password
```

## Environment variables

Override config on the fly:

| Var                   | Purpose                                                |
| --------------------- | ------------------------------------------------------ |
| `ZABLO_API_URL`      | Base URL of the Zablo API (default `https://api.zablo.io`) |
| `ZABLO_API_KEY`      | Bearer token (long-lived `vk_...` or session `vks_...`)|
| `ZABLO_PASSPHRASE`   | Client-side passphrase for AES-256-GCM decryption      |

## Workload identity federation (GitHub Actions, Kubernetes, GCP, AWS, Azure)

Instead of a long-lived API key, exchange a signed OIDC token from your runner
for a short-lived (~15 min) Zablo session token:

```yaml
# .github/workflows/deploy.yml
permissions:
  id-token: write   # <— tells GitHub to mint OIDC tokens for the job

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Get Zablo session
        run: |
          pip install zablo jq-cli
          TOKEN=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
                   "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=zablo.io" | jq -r .value)
          eval "$(zablo federate --subject-token "$TOKEN" --export)"
          zablo get prod/db/password  # or use zablo exec
        env:
          ZABLO_API_URL: https://api.acme.zablo.io
          ZABLO_PASSPHRASE: ${{ secrets.ZABLO_PASSPHRASE }}
```

No long-lived API key in `secrets.*`. The runner's ambient OIDC identity is the credential.

## Zero-knowledge model

Every secret you `put` is encrypted **on your machine** with an AES-256-GCM key derived from your passphrase (PBKDF2-SHA256, 600,000 iterations, 16-byte salt, 12-byte IV). The server receives only ciphertext.

Even if the Zablo database is compromised, an attacker cannot decrypt anything without your passphrase — which never leaves your machine. This is a mathematical property of the architecture, not a policy.

## Interop with the Node CLI (`vk`)

Zablo also ships a Node.js CLI. Both CLIs use the exact same envelope format —
a secret written by one can be read by the other, provided the same passphrase.

## Development

```sh
git clone https://github.com/zablo/zablo
cd zablo
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Build a distribution locally:

```sh
pip install build
python -m build
ls dist/
```

## Release

Tag & push:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The [publish-pypi.yml](.github/workflows/publish-pypi.yml) workflow runs the test matrix across Python 3.9–3.13, builds `sdist` + wheel, and publishes to PyPI via [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (no long-lived API tokens required).

## License

Apache-2.0. See [LICENSE](LICENSE).
