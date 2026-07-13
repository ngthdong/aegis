from __future__ import annotations

import secrets

DEK_LENGTH_BYTES = 32  # AES-256 key size
SALT_LENGTH_BYTES = 16  # Argon2id recommended minimum salt size


def generate_dek() -> bytes:
    """Generate a random 256-bit Data Encryption Key."""
    return secrets.token_bytes(DEK_LENGTH_BYTES)


def generate_salt() -> bytes:
    """
    Generate a random salt for KDF use. A fresh salt must be generated
    per vault initialization.
    """
    return secrets.token_bytes(SALT_LENGTH_BYTES)
