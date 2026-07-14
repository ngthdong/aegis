from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from aegis.core.service import (
    InvalidPassphrase,
    VaultAlreadyInitialized,
    VaultService,
)
from aegis.core.state import VaultState
from aegis.crypto.kdf import KdfParams
from aegis.storage.db import create_memory_engine
from aegis.storage.models import Base, VaultMetaRow
from aegis.storage.repository import SqlVaultRepository

_FAST_PARAMS = KdfParams(time_cost=1, memory_cost_kib=8, parallelism=1)


@pytest.fixture
def sql_vault() -> VaultService:
    engine = create_memory_engine()
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    repository = SqlVaultRepository(session_factory)
    return VaultService(repository, kdf_params=_FAST_PARAMS)


def test_full_lifecycle_against_real_sqlite(sql_vault: VaultService):
    assert sql_vault.status() == VaultState.UNINITIALIZED

    sql_vault.initialize("correct horse battery staple")
    assert sql_vault.status() == VaultState.SEALED

    sql_vault.unseal("correct horse battery staple")
    assert sql_vault.status() == VaultState.UNSEALED

    dek = sql_vault.get_dek()
    assert len(dek) == 32

    sql_vault.seal()
    assert sql_vault.status() == VaultState.SEALED


def test_cannot_initialize_twice_against_real_sqlite(sql_vault: VaultService):
    sql_vault.initialize("first")
    with pytest.raises(VaultAlreadyInitialized):
        sql_vault.initialize("second")


def test_wrong_passphrase_rejected_against_real_sqlite(sql_vault: VaultService):
    sql_vault.initialize("correct horse battery staple")
    with pytest.raises(InvalidPassphrase):
        sql_vault.unseal("wrong passphrase")
    assert sql_vault.status() == VaultState.SEALED


def test_dek_stable_across_seal_unseal_against_real_sqlite(sql_vault: VaultService):
    sql_vault.initialize("correct horse battery staple")

    sql_vault.unseal("correct horse battery staple")
    dek_first = sql_vault.get_dek()
    sql_vault.seal()

    sql_vault.unseal("correct horse battery staple")
    dek_second = sql_vault.get_dek()

    assert dek_first == dek_second


def test_corrupted_row_reported_as_invalid_passphrase(sql_vault: VaultService):
    """
    Same tamper test as Stage 1, but now the corruption happens in an
    actual SQL row rather than an in-memory dataclass -- proving the
    property survives the storage-layer swap, not just in theory.
    """
    sql_vault.initialize("correct horse battery staple")

    repo = sql_vault._repository  # type: ignore[attr-defined]
    meta = repo.load()
    tampered_ciphertext = bytearray(meta.dek_envelope.ciphertext)
    tampered_ciphertext[0] ^= 0xFF

    with sql_vault._repository._session_factory() as session:  # type: ignore[attr-defined]
        row = session.execute(select(VaultMetaRow).where(VaultMetaRow.id == 1)).scalar_one()
        row.dek_ciphertext = bytes(tampered_ciphertext)
        session.commit()

    with pytest.raises(InvalidPassphrase):
        sql_vault.unseal("correct horse battery staple")
