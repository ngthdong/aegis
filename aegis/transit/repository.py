from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from aegis.crypto.aead import Envelope
from aegis.storage.models import TransitKeyRow, TransitKeyVersionRow
from aegis.storage.unit_of_work import UnitOfWork
from aegis.transit.models import TransitKey, TransitKeyVersion


class TransitKeyRepository(Protocol):
    def get_by_name(self, name: str) -> TransitKey | None: ...
    def get_version(self, transit_key_id: str, version: int) -> TransitKeyVersion | None: ...
    def create_key(self, key: TransitKey, first_version: TransitKeyVersion) -> None: ...
    def add_version(self, version: TransitKeyVersion) -> None: ...
    def bump_current_version(self, transit_key_id: str, new_version: int) -> None: ...
    def set_disabled(self, name: str, disabled: bool) -> None: ...
    def destroy(self, name: str, destroyed_at: datetime) -> None: ...


class InMemoryTransitKeyRepository:
    def __init__(self) -> None:
        self._keys: dict[str, TransitKey] = {}
        self._versions: dict[str, dict[int, TransitKeyVersion]] = {}

    def get_by_name(self, name: str) -> TransitKey | None:
        return self._keys.get(name)

    def get_version(self, transit_key_id: str, version: int) -> TransitKeyVersion | None:
        return self._versions.get(transit_key_id, {}).get(version)

    def create_key(self, key: TransitKey, first_version: TransitKeyVersion) -> None:
        self._keys[key.name] = key
        self._versions[key.id] = {1: first_version}

    def add_version(self, version: TransitKeyVersion) -> None:
        self._versions.setdefault(version.transit_key_id, {})[version.version] = version

    def bump_current_version(self, transit_key_id: str, new_version: int) -> None:
        for name, key in self._keys.items():
            if key.id == transit_key_id:
                self._keys[name] = replace(key, current_version=new_version)
                return

    def set_disabled(self, name: str, disabled: bool) -> None:
        existing = self._keys.get(name)
        if existing is not None:
            self._keys[name] = replace(existing, disabled=disabled)

    def destroy(self, name: str, destroyed_at: datetime) -> None:
        existing = self._keys.get(name)
        if existing is None:
            return
        self._keys[name] = replace(existing, destroyed_at=destroyed_at)
        for version_num, version_row in self._versions.get(existing.id, {}).items():
            self._versions[existing.id][version_num] = replace(
                version_row, wrapped_key=None, public_key=None
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

    def get_version(self, transit_key_id: str, version: int) -> TransitKeyVersion | None:
        with UnitOfWork(self._session_factory) as uow:
            row = uow.session.execute(
                select(TransitKeyVersionRow).where(
                    TransitKeyVersionRow.transit_key_id == transit_key_id,
                    TransitKeyVersionRow.version == version,
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            return _row_to_version(row)

    def create_key(self, key: TransitKey, first_version: TransitKeyVersion) -> None:
        with UnitOfWork(self._session_factory) as uow:
            uow.session.add(
                TransitKeyRow(
                    id=key.id,
                    name=key.name,
                    owner_id=key.owner_id,
                    key_type=key.key_type,
                    algorithm=key.algorithm,
                    current_version=key.current_version,
                    disabled=key.disabled,
                    destroyed_at=None,
                    created_at=key.created_at.isoformat(),
                )
            )
            uow.session.add(_version_to_row(first_version))
            uow.commit()

    def add_version(self, version: TransitKeyVersion) -> None:
        with UnitOfWork(self._session_factory) as uow:
            uow.session.add(_version_to_row(version))
            uow.commit()

    def bump_current_version(self, transit_key_id: str, new_version: int) -> None:
        with UnitOfWork(self._session_factory) as uow:
            row = uow.session.execute(
                select(TransitKeyRow).where(TransitKeyRow.id == transit_key_id)
            ).scalar_one_or_none()
            if row is not None:
                row.current_version = new_version
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
            key_row = uow.session.execute(
                select(TransitKeyRow).where(TransitKeyRow.name == name)
            ).scalar_one_or_none()
            if key_row is None:
                return
            key_row.destroyed_at = destroyed_at.isoformat()

            version_rows = (
                uow.session.execute(
                    select(TransitKeyVersionRow).where(
                        TransitKeyVersionRow.transit_key_id == key_row.id
                    )
                )
                .scalars()
                .all()
            )
            for version_row in version_rows:
                version_row.key_nonce = None
                version_row.wrapped_key_ciphertext = None
                version_row.public_key = None
            uow.commit()


def _row_to_key(row: TransitKeyRow) -> TransitKey:
    return TransitKey(
        id=row.id,
        name=row.name,
        owner_id=row.owner_id,
        key_type=row.key_type,  # type: ignore[arg-type]
        algorithm=row.algorithm,
        current_version=row.current_version,
        disabled=row.disabled,
        destroyed_at=datetime.fromisoformat(row.destroyed_at) if row.destroyed_at else None,
        created_at=datetime.fromisoformat(row.created_at),
    )


def _row_to_version(row: TransitKeyVersionRow) -> TransitKeyVersion:
    wrapped_key = (
        Envelope(nonce=row.key_nonce, ciphertext=row.wrapped_key_ciphertext)
        if row.key_nonce is not None and row.wrapped_key_ciphertext is not None
        else None
    )
    return TransitKeyVersion(
        id=row.id,
        transit_key_id=row.transit_key_id,
        version=row.version,
        wrapped_key=wrapped_key,
        public_key=row.public_key,
        created_at=datetime.fromisoformat(row.created_at),
    )


def _version_to_row(version: TransitKeyVersion) -> TransitKeyVersionRow:
    return TransitKeyVersionRow(
        id=version.id,
        transit_key_id=version.transit_key_id,
        version=version.version,
        key_nonce=version.wrapped_key.nonce if version.wrapped_key else None,
        wrapped_key_ciphertext=version.wrapped_key.ciphertext if version.wrapped_key else None,
        public_key=version.public_key,
        created_at=version.created_at.isoformat(),
    )
