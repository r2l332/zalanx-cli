"""
Zero-knowledge client-side encryption.

Envelope versions
-----------------
v1 (legacy, decrypt-only for new clients):
    KDF   = PBKDF2-HMAC-SHA256, 600,000 iterations
    Cipher = AES-256-GCM

v2 (default for new writes since zablo-cli 0.3.0):
    KDF   = Argon2id, m=64 MiB, t=3, p=1  (OWASP "strong" tier)
    Cipher = AES-256-GCM

Both:
    * 256-bit AES key, 128-bit GCM auth tag
    * 16-byte random salt (public, per-secret)
    * 12-byte random IV (public, per-secret)
    * Base64 (standard, padded) on the wire

Version numbers are self-describing: v2 *always* means the exact Argon2id
parameters above. To harden further, mint a new version (v3) with new fixed
parameters — old secrets keep decrypting under their original version.

Set env var ZABLO_LEGACY_KDF=1 to force v1 output (FIPS-only environments).
"""

from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_AES_KEY_BYTES = 32          # 256 bits
_SALT_LEN = 16
_IV_LEN = 12

# v1: PBKDF2 (fixed)
_PBKDF2_ITERATIONS = 600_000

# v2: Argon2id (fixed; OWASP "strong" tier -> ~350-500 ms on modern CPU)
_ARGON2_MEM_KIB = 65536      # 64 MiB
_ARGON2_TIME_COST = 3
_ARGON2_PARALLELISM = 1

_LATEST_VERSION = 2


@dataclass
class EncryptedPayload:
    """Envelope produced by encrypt() and consumed by decrypt().

    Only `ciphertext`, `iv`, `salt`, and `version` cross the wire to the
    server -- the KDF and its parameters are derived from `version` alone
    on both sides.
    """

    ciphertext: str  # base64
    iv: str          # base64
    salt: str        # base64
    version: int = _LATEST_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "ciphertext": self.ciphertext,
            "iv": self.iv,
            "salt": self.salt,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, d: dict[str, object]) -> "EncryptedPayload":
        return cls(
            ciphertext=str(d["ciphertext"]),
            iv=str(d["iv"]),
            salt=str(d["salt"]),
            version=int(d.get("version", 1)),  # type: ignore[arg-type]
        )


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _derive_key(passphrase: str, salt: bytes, version: int) -> bytes:
    """Derive a 32-byte AES key for the given envelope version."""
    if version == 1:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=_AES_KEY_BYTES,
            salt=salt,
            iterations=_PBKDF2_ITERATIONS,
        )
        return kdf.derive(passphrase.encode("utf-8"))
    if version == 2:
        return hash_secret_raw(
            secret=passphrase.encode("utf-8"),
            salt=salt,
            time_cost=_ARGON2_TIME_COST,
            memory_cost=_ARGON2_MEM_KIB,
            parallelism=_ARGON2_PARALLELISM,
            hash_len=_AES_KEY_BYTES,
            type=Type.ID,
        )
    raise ValueError(f"unsupported envelope version: {version}")


def _use_legacy_kdf() -> bool:
    return os.environ.get("ZABLO_LEGACY_KDF", "").strip() not in ("", "0", "false", "False")


def _target_version() -> int:
    return 1 if _use_legacy_kdf() else _LATEST_VERSION


def encrypt(plaintext: str, passphrase: str) -> EncryptedPayload:
    """Encrypt `plaintext` with a key derived from `passphrase`.

    Uses v2 (Argon2id) by default. Set ZABLO_LEGACY_KDF=1 to emit v1 (PBKDF2)
    envelopes for FIPS-only environments.
    """
    version = _target_version()
    salt = secrets.token_bytes(_SALT_LEN)
    iv = secrets.token_bytes(_IV_LEN)
    key = _derive_key(passphrase, salt, version)
    aes = AESGCM(key)
    ct = aes.encrypt(iv, plaintext.encode("utf-8"), associated_data=None)
    return EncryptedPayload(
        ciphertext=_b64e(ct),
        iv=_b64e(iv),
        salt=_b64e(salt),
        version=version,
    )


def decrypt(payload: EncryptedPayload, passphrase: str) -> str:
    """Decrypt an EncryptedPayload back to plaintext.

    Handles all supported envelope versions transparently.
    """
    salt = _b64d(payload.salt)
    iv = _b64d(payload.iv)
    ct = _b64d(payload.ciphertext)
    key = _derive_key(passphrase, salt, payload.version)
    aes = AESGCM(key)
    pt = aes.decrypt(iv, ct, associated_data=None)
    return pt.decode("utf-8")


def wipe_string(s: str) -> None:
    """
    NO-OP.

    Python strings are immutable and often interned; there is no safe,
    portable way to zero them from userland Python. Attempting to do so via
    ctypes.memset() can (and did) corrupt CPython's internal state.

    Real defence-in-depth against memory-scraping requires OS-level primitives
    (`mlock`, secure allocators, ephemeral tmpfs) which are out of scope for a
    userland CLI. Callers should minimize plaintext lifetime by fetching only
    when needed and letting the reference drop out of scope.
    """
    del s  # keep signature stable but do nothing


__all__ = [
    "EncryptedPayload",
    "encrypt",
    "decrypt",
    "wipe_string",
]


# ---------------------------------------------------------------------------
# Self-test: round-trip v1 + v2 to make sure both paths work.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    passphrase = "test-passphrase-do-not-use"
    plaintext = "hello from python"

    # v2 (default)
    v2 = encrypt(plaintext, passphrase)
    assert v2.version == 2, v2.version
    assert decrypt(v2, passphrase) == plaintext

    # v1 (legacy) via env var
    os.environ["ZABLO_LEGACY_KDF"] = "1"
    try:
        v1 = encrypt(plaintext, passphrase)
        assert v1.version == 1, v1.version
        assert decrypt(v1, passphrase) == plaintext
    finally:
        os.environ.pop("ZABLO_LEGACY_KDF", None)

    # Wire-format compatibility: envelope from an older client (bare v1)
    legacy_wire = {
        "version": 1,
        "salt": v1.salt,
        "iv": v1.iv,
        "ciphertext": v1.ciphertext,
    }
    reconstructed = EncryptedPayload.from_dict(legacy_wire)
    assert decrypt(reconstructed, passphrase) == plaintext

    print("crypto self-test ok (v1 + v2 round-trip, wire-compat)")
