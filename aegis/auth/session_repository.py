from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from aegis.auth.session_service import SessionRecord
from aegis.storage.models import SessionRow
from aegis.storage.unit_of_work import UnitOfWork


class InMemorySessionRepository:
    def __init__(self) -> None:
        self._sessions: dict[str, SessionRecord] = {}

    def save(self, session: SessionRecord) -> None:
        self._sessions[session.token_hash] = session

    def get_by_token_hash(self, token_hash: str) -> SessionRecord | None:
        return self._sessions.get(token_hash)

    def revoke(self, token_hash: str, revoked_at: datetime) -> None:
        existing = self._sessions.get(token_hash)
        if existing is not None:
            from dataclasses import replace

            self._sessions[token_hash] = replace(existing, revoked_at=revoked_at)


class SqlSessionRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def save(self, session: SessionRecord) -> None:
        with UnitOfWork(self._session_factory) as uow:
            row = SessionRow(
                id=session.id,
                user_id=session.user_id,
                username=session.username,
                role=session.role,
                token_hash=session.token_hash,
                created_at=session.created_at.isoformat(),
                expires_at=session.expires_at.isoformat(),
                revoked_at=session.revoked_at.isoformat() if session.revoked_at else None,
            )
            uow.session.add(row)
            uow.commit()

    def get_by_token_hash(self, token_hash: str) -> SessionRecord | None:
        with UnitOfWork(self._session_factory) as uow:
            row = uow.session.execute(
                select(SessionRow).where(SessionRow.token_hash == token_hash)
            ).scalar_one_or_none()
            if row is None:
                return None
            return _row_to_record(row)

    def revoke(self, token_hash: str, revoked_at: datetime) -> None:
        with UnitOfWork(self._session_factory) as uow:
            row = uow.session.execute(
                select(SessionRow).where(SessionRow.token_hash == token_hash)
            ).scalar_one_or_none()
            if row is not None:
                row.revoked_at = revoked_at.isoformat()
                uow.commit()


def _row_to_record(row: SessionRow) -> SessionRecord:
    return SessionRecord(
        id=row.id,
        user_id=row.user_id,
        username=row.username,
        token_hash=row.token_hash,
        created_at=datetime.fromisoformat(row.created_at),
        expires_at=datetime.fromisoformat(row.expires_at),
        revoked_at=datetime.fromisoformat(row.revoked_at) if row.revoked_at else None,
        role=row.role,
    )
