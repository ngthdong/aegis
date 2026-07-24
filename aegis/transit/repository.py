from __future__ import annotations

from dataclasses import replace
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
    def set_disabled(self, name: str, disabled: bool) -> None: ...
    def destroy(self, name: str, destroyed_at: datetime) -> None: ...


class InMemoryTransitKeyRepository:
    def __init__(self) -> None:
        self._keys: dict[str, TransitKey] = {}

    def get_by_name(self, name: str) -> TransitKey | None:
        return self._keys.get(name)

    def save(self, key: TransitKey) -> None:
        self._keys[key.name] = key

    def set_disabled(self, name: str, disabled: bool) -> None:
        existing = self._keys.get(name)
        if existing is not None:
            self._keys[name] = replace(existing, disabled=disabled)

    def destroy(self, name: str, destroyed_at: datetime) -> None:
        existing = self._keys.get(name)
        if existing is not None:
            self._keys[name] = replace(
                existing, wrapped_key=None, public_key=None, destroyed_at=destroyed_at
            )


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
                key_type=key.key_type,
                algorithm=key.algorithm,
                key_nonce=key.wrapped_key.nonce if key.wrapped_key else None,
                wrapped_key_ciphertext=key.wrapped_key.ciphertext if key.wrapped_key else None,
                public_key=key.public_key,
                disabled=key.disabled,
                destroyed_at=key.destroyed_at.isoformat() if key.destroyed_at else None,
                created_at=key.created_at.isoformat(),
            )
            uow.session.add(row)
            uow.commit()

    def set_disabled(self, name: str, disabled: bool) -> None:
        with UnitOfWork(self._session_factory) as uow:
            row = uow.session.execute(
                select(TransitKeyRow).where(TransitKeyRow.name == name)
            ).scalar_one_or_none()
            if row is not None:
                row.disabled = disabled
                uow.commit()

    def destroy(self, name: str, destroyed_at: datetime) -> None:
        with UnitOfWork(self._session_factory) as uow:
            row = uow.session.execute(
                select(TransitKeyRow).where(TransitKeyRow.name == name)
            ).scalar_one_or_none()
            if row is not None:
                row.key_nonce = None
                row.wrapped_key_ciphertext = None
                row.public_key = None
                row.destroyed_at = destroyed_at.isoformat()
                uow.commit()


def _row_to_key(row: TransitKeyRow) -> TransitKey:
    wrapped_key = (
        Envelope(nonce=row.key_nonce, ciphertext=row.wrapped_key_ciphertext)
        if row.key_nonce is not None and row.wrapped_key_ciphertext is not None
        else None
    )
    return TransitKey(
        id=row.id,
        name=row.name,
        owner_id=row.owner_id,
        key_type=row.key_type,  # type: ignore[arg-type]
        algorithm=row.algorithm,
        wrapped_key=wrapped_key,
        public_key=row.public_key,
        disabled=row.disabled,
        destroyed_at=datetime.fromisoformat(row.destroyed_at) if row.destroyed_at else None,
        created_at=datetime.fromisoformat(row.created_at),
    )
