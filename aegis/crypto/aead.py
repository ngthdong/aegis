from __future__ import annotations

import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LENGTH_BYTES = 12  # 96 bits standard GCM nonce size
KEY_LENGTH_BYTES = 32  # AES-256


class DecryptionError(Exception):
    """
    Raised when ciphertext fails authentication: wrong key,
    tampered ciphertext, or mismatched associated data.
    Deliberately not split into more specific subclasses.
    AEAD's security property is that these failure modes are
    indistinguishable from the outside.
    """


@dataclass(frozen=True, slots=True)
class Envelope:
    """
    A nonce + ciphertext pair that is the unit of storage for AEAD-encrypted data.
    """

    nonce: bytes
    ciphertext: bytes  # includes the GCM authentication tag


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> Envelope:
    """
    Encrypt "plaintext" under "key", authenticating "aad" alongside it.
    A fresh random nonce is generated on every call.
    """
    if len(key) != KEY_LENGTH_BYTES:
        raise ValueError(f"key must be {KEY_LENGTH_BYTES} bytes, got {len(key)}")

    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_LENGTH_BYTES)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return Envelope(nonce=nonce, ciphertext=ciphertext)


def decrypt(key: bytes, envelope: Envelope, aad: bytes = b"") -> bytes:
    """
    Decrypt `envelope` under `key`, verifying `aad` matches what was
    supplied at encryption time. Raises DecryptionError on any failure.
    """
    if len(key) != KEY_LENGTH_BYTES:
        raise ValueError(f"key must be {KEY_LENGTH_BYTES} bytes, got {len(key)}")

    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(envelope.nonce, envelope.ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError(
            "decryption failed: invalid key, aad, or tampered ciphertext"
        ) from exc
