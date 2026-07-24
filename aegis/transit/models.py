from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from aegis.crypto.aead import Envelope


@dataclass(frozen=True, slots=True)
class TransitKey:
    id: str
    name: str
    owner_id: str
    algorithm: str
    wrapped_key: Envelope  # the per-key AES-256 key
    disabled: bool
    created_at: datetime
