from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class User:
    id: str
    username: str
    password_hash: str
    failed_login_count: int
    locked_until: datetime | None
    created_at: datetime
