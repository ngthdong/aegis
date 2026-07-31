from __future__ import annotations

import struct
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


VERSION_TAG_LENGTH_BYTES = 4
_VERSION_TAG_FORMAT = ">I"


def pack_version_tag(version: int) -> bytes:
    return struct.pack(_VERSION_TAG_FORMAT, version)


def unpack_version_tag(blob: bytes) -> tuple[int, bytes] | None:
    if len(blob) < VERSION_TAG_LENGTH_BYTES:
        return None
    version = struct.unpack(_VERSION_TAG_FORMAT, blob[:VERSION_TAG_LENGTH_BYTES])[0]
    return version, blob[VERSION_TAG_LENGTH_BYTES:]


@dataclass(frozen=True, slots=True)
class TransitKey:
    id: str
    name: str
    owner_id: str
    key_type: TransitKeyType
    algorithm: str
    current_version: int
    disabled: bool
    destroyed_at: datetime | None
    created_at: datetime

    @property
    def is_destroyed(self) -> bool:
        return self.destroyed_at is not None


@dataclass(frozen=True, slots=True)
class TransitKeyVersion:
    id: str
    transit_key_id: str
    version: int
    wrapped_key: Envelope | None
    public_key: bytes | None
    created_at: datetime
