"""Round-trip crypto tests."""

import base64

import pytest

from zalanx.crypto import EncryptedPayload, decrypt, encrypt


def test_roundtrip():
    payload = encrypt("hello world", "correct-horse-battery-staple")
    assert decrypt(payload, "correct-horse-battery-staple") == "hello world"


def test_wrong_passphrase_raises():
    payload = encrypt("secret", "right")
    with pytest.raises(Exception):
        decrypt(payload, "wrong")


def test_payload_serialization():
    payload = encrypt("x", "pp")
    d = payload.to_dict()
    assert set(d.keys()) == {"ciphertext", "iv", "salt", "version"}
    p2 = EncryptedPayload.from_dict(d)
    assert decrypt(p2, "pp") == "x"


def test_salt_and_iv_lengths():
    payload = encrypt("x", "pp")
    assert len(base64.b64decode(payload.salt)) == 16
    assert len(base64.b64decode(payload.iv)) == 12


def test_two_encryptions_produce_different_ciphertexts():
    a = encrypt("same", "pp")
    b = encrypt("same", "pp")
    # Different salt + IV, so different ciphertext
    assert a.ciphertext != b.ciphertext
    assert a.salt != b.salt
    assert a.iv != b.iv
    # But both decrypt to the same plaintext
    assert decrypt(a, "pp") == decrypt(b, "pp") == "same"
