from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

PRIVATE_KEY_LENGTH_BYTES = 32
PUBLIC_KEY_LENGTH_BYTES = 32


@dataclass(frozen=True, slots=True)
class Ed25519KeyPair:
    private_key_bytes: bytes
    public_key_bytes: bytes


def generate_keypair() -> Ed25519KeyPair:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return Ed25519KeyPair(
        private_key_bytes=private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        ),
        public_key_bytes=public_key.public_bytes(Encoding.Raw, PublicFormat.Raw),
    )


def sign(private_key_bytes: bytes, message: bytes) -> bytes:
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return private_key.sign(message)


def verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        public_key.verify(signature, message)
    except InvalidSignature:
        return False
    return True
