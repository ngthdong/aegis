from __future__ import annotations

from datetime import datetime
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from aegis.crypto.aead import Envelope
from aegis.kv.models import Secret
from aegis.storage.models import SecretRow
from aegis.storage.unit_of_work import UnitOfWork


class SecretRepository(Protocol):
    def get_by_path(self, path: str) -> Secret | None: ...
    def save(self, secret: Secret) -> None: ...
    def delete(self, path: str) -> None: ...


class InMemorySecretRepository:
    def __init__(self) -> None:
        self._secrets: dict[str, Secret] = {}

    def get_by_path(self, path: str) -> Secret | None:
        return self._secrets.get(path)

    def save(self, secret: Secret) -> None:
        self._secrets[secret.path] = secret

    def delete(self, path: str) -> None:
        self._secrets.pop(path, None)


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

    def save(self, secret: Secret) -> None:
        with UnitOfWork(self._session_factory) as uow:
            existing = uow.session.execute(
                select(SecretRow).where(SecretRow.path == secret.path)
            ).scalar_one_or_none()

            if existing is not None:
                existing.owner_id = secret.owner_id
                existing.nonce = secret.envelope.nonce
                existing.ciphertext = secret.envelope.ciphertext
                existing.updated_at = secret.updated_at.isoformat()
            else:
                row = SecretRow(
                    id=secret.id,
                    path=secret.path,
                    owner_id=secret.owner_id,
                    nonce=secret.envelope.nonce,
                    ciphertext=secret.envelope.ciphertext,
                    created_at=secret.created_at.isoformat(),
                    updated_at=secret.updated_at.isoformat(),
                )
                uow.session.add(row)
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
        envelope=Envelope(nonce=row.nonce, ciphertext=row.ciphertext),
        created_at=datetime.fromisoformat(row.created_at),
        updated_at=datetime.fromisoformat(row.updated_at),
    )
