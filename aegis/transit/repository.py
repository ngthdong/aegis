from __future__ import annotations

from datetime import datetime
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from aegis.crypto.aead import Envelope
from aegis.storage.models import TransitKeyRow
from aegis.storage.unit_of_work import UnitOfWork
from aegis.transit.models import TransitKey


class TransitKeyRepository(Protocol):
    def get_by_name(self, name: str) -> TransitKey | None: ...
    def save(self, key: TransitKey) -> None: ...


class InMemoryTransitKeyRepository:
    def __init__(self) -> None:
        self._keys: dict[str, TransitKey] = {}

    def get_by_name(self, name: str) -> TransitKey | None:
        return self._keys.get(name)

    def save(self, key: TransitKey) -> None:
        self._keys[key.name] = key


class SqlTransitKeyRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def get_by_name(self, name: str) -> TransitKey | None:
        with UnitOfWork(self._session_factory) as uow:
            row = uow.session.execute(
                select(TransitKeyRow).where(TransitKeyRow.name == name)
            ).scalar_one_or_none()
            if row is None:
                return None
            return _row_to_key(row)

    def save(self, key: TransitKey) -> None:
        with UnitOfWork(self._session_factory) as uow:
            row = TransitKeyRow(
                id=key.id,
                name=key.name,
                owner_id=key.owner_id,
                algorithm=key.algorithm,
                key_nonce=key.wrapped_key.nonce,
                wrapped_key_ciphertext=key.wrapped_key.ciphertext,
                disabled=key.disabled,
                created_at=key.created_at.isoformat(),
            )
            uow.session.add(row)
            uow.commit()


def _row_to_key(row: TransitKeyRow) -> TransitKey:
    return TransitKey(
        id=row.id,
        name=row.name,
        owner_id=row.owner_id,
        algorithm=row.algorithm,
        wrapped_key=Envelope(nonce=row.key_nonce, ciphertext=row.wrapped_key_ciphertext),
        disabled=row.disabled,
        created_at=datetime.fromisoformat(row.created_at),
    )
