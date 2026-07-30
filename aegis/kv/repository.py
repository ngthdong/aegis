from __future__ import annotations

from datetime import datetime
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from aegis.crypto.aead import Envelope
from aegis.kv.models import Secret, SecretVersion
from aegis.storage.models import SecretRow, SecretVersionRow
from aegis.storage.unit_of_work import UnitOfWork


class SecretRepository(Protocol):
    def get_by_path(self, path: str) -> Secret | None: ...
    def get_version(self, secret_id: str, version: int) -> SecretVersion | None: ...
    def create_secret(self, secret: Secret) -> None: ...
    def add_version(self, version: SecretVersion) -> None: ...

    def bump_current_version(
        self, secret_id: str, new_version: int, updated_at: datetime
    ) -> None: ...

    def delete(self, path: str) -> None: ...


class InMemorySecretRepository:
    def __init__(self) -> None:
        self._secrets: dict[str, Secret] = {}
        self._versions: dict[str, dict[int, SecretVersion]] = {}

    def get_by_path(self, path: str) -> Secret | None:
        return self._secrets.get(path)

    def get_version(self, secret_id: str, version: int) -> SecretVersion | None:
        return self._versions.get(secret_id, {}).get(version)

    def create_secret(self, secret: Secret) -> None:
        self._secrets[secret.path] = secret
        self._versions[secret.id] = {}

    def add_version(self, version: SecretVersion) -> None:
        self._versions.setdefault(version.secret_id, {})[version.version] = version

    def bump_current_version(self, secret_id: str, new_version: int, updated_at: datetime) -> None:
        from dataclasses import replace

        for path, secret in self._secrets.items():
            if secret.id == secret_id:
                self._secrets[path] = replace(
                    secret, current_version=new_version, updated_at=updated_at
                )
                return

    def delete(self, path: str) -> None:
        secret = self._secrets.pop(path, None)
        if secret is not None:
            self._versions.pop(secret.id, None)


class SqlSecretRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def get_by_path(self, path: str) -> Secret | None:
        with UnitOfWork(self._session_factory) as uow:
            row = uow.session.execute(
                select(SecretRow).where(SecretRow.path == path)
            ).scalar_one_or_none()
            if row is None:
                return None
            return _row_to_secret(row)

    def get_version(self, secret_id: str, version: int) -> SecretVersion | None:
        with UnitOfWork(self._session_factory) as uow:
            row = uow.session.execute(
                select(SecretVersionRow).where(
                    SecretVersionRow.secret_id == secret_id,
                    SecretVersionRow.version == version,
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            return _row_to_version(row)

    def create_secret(self, secret: Secret) -> None:
        with UnitOfWork(self._session_factory) as uow:
            row = SecretRow(
                id=secret.id,
                path=secret.path,
                owner_id=secret.owner_id,
                current_version=secret.current_version,
                created_at=secret.created_at.isoformat(),
                updated_at=secret.updated_at.isoformat(),
            )
            uow.session.add(row)
            uow.commit()

    def add_version(self, version: SecretVersion) -> None:
        with UnitOfWork(self._session_factory) as uow:
            row = SecretVersionRow(
                id=version.id,
                secret_id=version.secret_id,
                version=version.version,
                nonce=version.envelope.nonce,
                ciphertext=version.envelope.ciphertext,
                created_at=version.created_at.isoformat(),
            )
            uow.session.add(row)
            uow.commit()

    def bump_current_version(self, secret_id: str, new_version: int, updated_at: datetime) -> None:
        with UnitOfWork(self._session_factory) as uow:
            row = uow.session.execute(
                select(SecretRow).where(SecretRow.id == secret_id)
            ).scalar_one_or_none()
            if row is not None:
                row.current_version = new_version
                row.updated_at = updated_at.isoformat()
                uow.commit()

    def delete(self, path: str) -> None:
        with UnitOfWork(self._session_factory) as uow:
            row = uow.session.execute(
                select(SecretRow).where(SecretRow.path == path)
            ).scalar_one_or_none()
            if row is not None:
                uow.session.delete(row)
                uow.commit()


def _row_to_secret(row: SecretRow) -> Secret:
    return Secret(
        id=row.id,
        path=row.path,
        owner_id=row.owner_id,
        current_version=row.current_version,
        created_at=row.created_at_dt,
        updated_at=datetime.fromisoformat(row.updated_at),
    )


def _row_to_version(row: SecretVersionRow) -> SecretVersion:
    return SecretVersion(
        id=row.id,
        secret_id=row.secret_id,
        version=row.version,
        envelope=Envelope(nonce=row.nonce, ciphertext=row.ciphertext),
        created_at=datetime.fromisoformat(row.created_at),
    )
