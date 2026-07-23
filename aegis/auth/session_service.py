from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from aegis.common.clock import Clock

TOKEN_LENGTH_BYTES = 32
DEFAULT_SESSION_TTL = timedelta(hours=12)


@dataclass(frozen=True, slots=True)
class SessionRecord:
    id: str
    user_id: str
    username: str
    token_hash: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: str
    username: str


class SessionRepository(Protocol):
    def save(self, session: SessionRecord) -> None: ...
    def get_by_token_hash(self, token_hash: str) -> SessionRecord | None: ...
    def revoke(self, token_hash: str, revoked_at: datetime) -> None: ...


class SessionNotFound(Exception):
    pass


class SessionExpired(Exception):
    pass


class SessionRevoked(Exception):
    pass


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class SessionService:
    def __init__(
        self,
        repository: SessionRepository,
        clock: Clock,
        ttl: timedelta = DEFAULT_SESSION_TTL,
    ) -> None:
        self._repository = repository
        self._clock = clock
        self._ttl = ttl

    @property
    def ttl(self) -> timedelta:
        return self._ttl

    def create(self, user_id: str, username: str) -> str:
        raw_token = secrets.token_urlsafe(TOKEN_LENGTH_BYTES)
        now = self._clock.now()
        record = SessionRecord(
            id=secrets.token_hex(16),
            user_id=user_id,
            username=username,
            token_hash=_hash_token(raw_token),
            created_at=now,
            expires_at=now + self._ttl,
            revoked_at=None,
        )
        self._repository.save(record)
        return raw_token

    def validate(self, raw_token: str) -> Principal:
        token_hash = _hash_token(raw_token)
        record = self._repository.get_by_token_hash(token_hash)
        if record is None:
            raise SessionNotFound("session not found")
        if record.revoked_at is not None:
            raise SessionRevoked("session has been revoked")
        if self._clock.now() >= record.expires_at:
            raise SessionExpired("session has expired")
        return Principal(user_id=record.user_id, username=record.username)

    def revoke(self, raw_token: str) -> None:
        token_hash = _hash_token(raw_token)
        self._repository.revoke(token_hash, self._clock.now())
