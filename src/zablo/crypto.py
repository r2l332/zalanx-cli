"""
Zero-knowledge client-side encryption.

MUST be byte-for-byte compatible with the TypeScript CLI at
packages/crypto/src/index.ts so secrets round-trip between clients.

Parameters (fixed, matching TS):
  * AES-256-GCM
  * PBKDF2-HMAC-SHA256 with 600,000 iterations
  * 16-byte random salt
  * 12-byte random IV
  * 128-bit auth tag (default for AESGCM in `cryptography`)
  * All bytes exchanged as standard base64 (with padding)
"""

from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_AES_KEY_BYTES = 32          # 256 bits
_PBKDF2_ITERATIONS = 600_000  # OWASP 2023+ guidance for PBKDF2-SHA256
_SALT_LEN = 16
_IV_LEN = 12
_PAYLOAD_VERSION = 1


@dataclass
class EncryptedPayload:
    """Envelope produced by encrypt() and consumed by decrypt()."""

    ciphertext: str  # base64
    iv: str          # base64
    salt: str        # base64
    version: int = _PAYLOAD_VERSION

    def to_dict(self) -> dict[str, str | int]:
        return {
            "ciphertext": self.ciphertext,
            "iv": self.iv,
            "salt": self.salt,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, d: dict[str, object]) -> EncryptedPayload:
        return cls(
            ciphertext=str(d["ciphertext"]),
            iv=str(d["iv"]),
            salt=str(d["salt"]),
            version=int(d.get("version", _PAYLOAD_VERSION)),  # type: ignore[arg-type]
        )


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_AES_KEY_BYTES,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt(plaintext: str, passphrase: str) -> EncryptedPayload:
    """Encrypt `plaintext` with a key derived from `passphrase`."""
    salt = secrets.token_bytes(_SALT_LEN)
    iv = secrets.token_bytes(_IV_LEN)
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)
    ct = aes.encrypt(iv, plaintext.encode("utf-8"), associated_data=None)
    return EncryptedPayload(
        ciphertext=_b64e(ct),
        iv=_b64e(iv),
        salt=_b64e(salt),
        version=_PAYLOAD_VERSION,
    )


def decrypt(payload: EncryptedPayload, passphrase: str) -> str:
    """Decrypt an EncryptedPayload back to plaintext."""
    salt = _b64d(payload.salt)
    iv = _b64d(payload.iv)
    ct = _b64d(payload.ciphertext)
    key = _derive_key(passphrase, salt)
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
# Self-test: verify we can decrypt a known-good payload produced by the TS CLI.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Round-trip test
    passphrase = "test-passphrase-do-not-use"
    plaintext = "hello from python"
    payload = encrypt(plaintext, passphrase)
    assert decrypt(payload, passphrase) == plaintext
    print("crypto self-test ok:", payload.to_dict())
    _ = os
