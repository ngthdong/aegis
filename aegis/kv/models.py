from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from aegis.crypto.aead import Envelope


@dataclass(frozen=True, slots=True)
class Secret:
    id: str
    path: str
    owner_id: str
    current_version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class SecretVersion:
    id: str
    secret_id: str
    version: int
    envelope: Envelope
    created_at: datetime
