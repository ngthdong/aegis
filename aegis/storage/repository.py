from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from aegis.core.service import VaultMeta
from aegis.crypto.aead import Envelope
from aegis.crypto.kdf import KdfParams
from aegis.storage.models import VaultMetaRow
from aegis.storage.unit_of_work import UnitOfWork


class SqlVaultRepository:
    def __init__(self, session_factory: sessionmaker) -> None:
        self._session_factory = session_factory

    def load(self) -> VaultMeta | None:
        with UnitOfWork(self._session_factory) as uow:
            row = uow.session.execute(
                select(VaultMetaRow).where(VaultMetaRow.id == 1)
            ).scalar_one_or_none()

            if row is None:
                return None

            return VaultMeta(
                kdf_salt=row.kdf_salt,
                kdf_params=KdfParams(
                    time_cost=row.kdf_time_cost,
                    memory_cost_kib=row.kdf_memory_cost_kib,
                    parallelism=row.kdf_parallelism,
                ),
                dek_envelope=Envelope(nonce=row.dek_nonce, ciphertext=row.dek_ciphertext),
                initialized_at=row.initialized_at_dt,
            )

    def save(self, meta: VaultMeta) -> None:
        with UnitOfWork(self._session_factory) as uow:
            existing = uow.session.execute(
                select(VaultMetaRow).where(VaultMetaRow.id == 1)
            ).scalar_one_or_none()

            if existing is not None:
                raise RuntimeError(
                    "refusing to overwrite existing vault_meta row; "
                    "VaultService should have rejected this via "
                    "VaultAlreadyInitialized before reaching the repository"
                )

            row = VaultMetaRow(
                id=1,
                kdf_salt=meta.kdf_salt,
                kdf_time_cost=meta.kdf_params.time_cost,
                kdf_memory_cost_kib=meta.kdf_params.memory_cost_kib,
                kdf_parallelism=meta.kdf_params.parallelism,
                dek_nonce=meta.dek_envelope.nonce,
                dek_ciphertext=meta.dek_envelope.ciphertext,
                initialized_at=_isoformat(meta.initialized_at),
            )
            uow.session.add(row)
            uow.commit()


def _isoformat(dt: datetime) -> str:
    return dt.isoformat()
