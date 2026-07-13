import pytest

from aegis.crypto.aead import KEY_LENGTH_BYTES, DecryptionError, Envelope, decrypt, encrypt
from aegis.crypto.random import generate_dek


def test_round_trip() -> None:
    key = generate_dek()
    plaintext = b"super secret value"
    envelope = encrypt(key, plaintext, aad=b"context")
    assert decrypt(key, envelope, aad=b"context") == plaintext


def test_tampered_ciphertext_is_rejected() -> None:
    key = generate_dek()
    envelope = encrypt(key, b"secret", aad=b"context")

    # Flip a single byte in the ciphertext. This is the tamper test.
    tampered = bytearray(envelope.ciphertext)
    tampered[0] ^= 0xFF

    tampered_envelope = Envelope(nonce=envelope.nonce, ciphertext=bytes(tampered))

    with pytest.raises(DecryptionError):
        decrypt(key, tampered_envelope, aad=b"context")


def test_wrong_key_is_rejected() -> None:
    key_a = generate_dek()
    key_b = generate_dek()
    envelope = encrypt(key_a, b"secret", aad=b"context")

    with pytest.raises(DecryptionError):
        decrypt(key_b, envelope, aad=b"context")


def test_mismatched_aad_is_rejected() -> None:
    key = generate_dek()
    envelope = encrypt(key, b"secret", aad=b"path/a")

    with pytest.raises(DecryptionError):
        decrypt(key, envelope, aad=b"path/b")


def test_two_encryptions_use_different_nonces() -> None:
    key = generate_dek()
    envelope_a = encrypt(key, b"same plaintext")
    envelope_b = encrypt(key, b"same plaintext")
    assert envelope_a.nonce != envelope_b.nonce
    assert envelope_a.ciphertext != envelope_b.ciphertext


def test_wrong_key_length_rejected() -> None:
    with pytest.raises(ValueError):
        encrypt(b"too short", b"plaintext")
    assert KEY_LENGTH_BYTES == 32
