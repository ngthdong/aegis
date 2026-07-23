from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from aegis.crypto.aead import Envelope


@dataclass(frozen=True, slots=True)
class Secret:
    id: str
    path: str
    owner_id: str
    envelope: Envelope
    created_at: datetime
    updated_at: datetime
