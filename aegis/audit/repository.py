from __future__ import annotations

import json
from typing import Protocol

from sqlalchemy.orm import Session, sessionmaker

from aegis.audit.models import AuditEvent
from aegis.storage.models import AuditLogRow
from aegis.storage.unit_of_work import UnitOfWork


class AuditRepository(Protocol):
    def save(self, event: AuditEvent) -> None: ...


class InMemoryAuditRepository:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def save(self, event: AuditEvent) -> None:
        self.events.append(event)


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
