from __future__ import annotations

import json
from datetime import datetime
from typing import Protocol

from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from aegis.audit.models import AuditEvent
from aegis.storage.models import AuditLogRow
from aegis.storage.unit_of_work import UnitOfWork


class AuditRepository(Protocol):
    def save(self, event: AuditEvent) -> None: ...
    def list_for_principal(
        self,
        principal_id: str,
        action: str | None,
        since: datetime | None,
        limit: int,
        offset: int,
    ) -> list[AuditEvent]: ...


class InMemoryAuditRepository:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def save(self, event: AuditEvent) -> None:
        self.events.append(event)

    def list_for_principal(
        self,
        principal_id: str,
        action: str | None,
        since: datetime | None,
        limit: int,
        offset: int,
    ) -> list[AuditEvent]:
        indexed = list(enumerate(self.events))
        matching = [
            (i, e)
            for i, e in indexed
            if e.principal_id == principal_id
            and (action is None or e.action == action)
            and (since is None or e.timestamp >= since)
        ]
        matching.sort(key=lambda pair: (pair[1].timestamp, pair[0]), reverse=True)
        return [e for _, e in matching[offset : offset + limit]]


class SqlAuditRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def save(self, event: AuditEvent) -> None:
        with UnitOfWork(self._session_factory) as uow:
            row = AuditLogRow(
                id=event.id,
                timestamp=event.timestamp.isoformat(),
                principal_id=event.principal_id,
                action=event.action,
                resource_type=event.resource_type,
                resource_id=event.resource_id,
                outcome=event.outcome,
                metadata_json=json.dumps(event.metadata),
            )
            uow.session.add(row)
            uow.commit()

    def list_for_principal(
        self,
        principal_id: str,
        action: str | None,
        since: datetime | None,
        limit: int,
        offset: int,
    ) -> list[AuditEvent]:
        with UnitOfWork(self._session_factory) as uow:
            stmt = select(AuditLogRow).where(AuditLogRow.principal_id == principal_id)
            if action is not None:
                stmt = stmt.where(AuditLogRow.action == action)
            if since is not None:
                stmt = stmt.where(AuditLogRow.timestamp >= since.isoformat())

            stmt = (
                stmt.order_by(AuditLogRow.timestamp.desc(), text("rowid DESC"))
                .limit(limit)
                .offset(offset)
            )

            rows = uow.session.execute(stmt).scalars().all()
            return [_row_to_event(row) for row in rows]


def _row_to_event(row: AuditLogRow) -> AuditEvent:
    return AuditEvent(
        id=row.id,
        timestamp=datetime.fromisoformat(row.timestamp),
        principal_id=row.principal_id,
        action=row.action,
        resource_type=row.resource_type,
        resource_id=row.resource_id,
        outcome=row.outcome,  # type: ignore[arg-type]
        metadata=json.loads(row.metadata_json),
    )
