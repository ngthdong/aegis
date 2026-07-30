from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from aegis.crypto.aead import Envelope

TransitKeyType = Literal["symmetric", "asymmetric_sign"]

MessageType = Literal["RAW", "DIGEST"]
HashAlgorithm = Literal["SHA256", "SHA512"]

DIGEST_LENGTH_BYTES: dict[HashAlgorithm, int] = {
    "SHA256": 32,
    "SHA512": 64,
}


@dataclass(frozen=True, slots=True)
class TransitKey:
    id: str
    name: str
    owner_id: str
    key_type: TransitKeyType
    algorithm: str
    wrapped_key: Envelope | None
    public_key: bytes | None
    disabled: bool
    destroyed_at: datetime | None
    created_at: datetime

    @property
    def is_destroyed(self) -> bool:
        return self.destroyed_at is not None
