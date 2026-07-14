from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import sessionmaker

from aegis.core.service import VaultMeta
from aegis.crypto.aead import Envelope
from aegis.crypto.kdf import KdfParams
from aegis.storage.db import create_memory_engine
from aegis.storage.models import Base
from aegis.storage.repository import SqlVaultRepository


@pytest.fixture
def session_factory() -> sessionmaker:
    engine = create_memory_engine()
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture
def repository(session_factory: sessionmaker) -> SqlVaultRepository:
    return SqlVaultRepository(session_factory)


def _sample_meta() -> VaultMeta:
    return VaultMeta(
        kdf_salt=b"0123456789abcdef",
        kdf_params=KdfParams(time_cost=1, memory_cost_kib=8, parallelism=1),
        dek_envelope=Envelope(nonce=b"123456789012", ciphertext=b"fake-ciphertext-bytes"),
        initialized_at=datetime.now(UTC),
    )


def test_load_returns_none_when_empty(repository: SqlVaultRepository):
    assert repository.load() is None


def test_save_then_load_round_trips_exactly(repository: SqlVaultRepository):
    meta = _sample_meta()
    repository.save(meta)

    loaded = repository.load()
    assert loaded is not None
    assert loaded.kdf_salt == meta.kdf_salt
    assert loaded.kdf_params == meta.kdf_params
    assert loaded.dek_envelope.nonce == meta.dek_envelope.nonce
    assert loaded.dek_envelope.ciphertext == meta.dek_envelope.ciphertext
    # Compare timestamps at second resolution - ISO roundtrip through
    # SQLite text storage is exact, but this guards against future
    # changes to the serialization format silently truncating precision.
    assert loaded.initialized_at.isoformat() == meta.initialized_at.isoformat()


def test_save_refuses_to_overwrite_existing_row(repository: SqlVaultRepository):
    repository.save(_sample_meta())

    with pytest.raises(RuntimeError):
        repository.save(_sample_meta())


def test_repository_survives_across_separate_sessions(session_factory: sessionmaker):
    """
    Each call to load()/save() opens and closes its own UnitOfWork/session
    (see SqlVaultRepository). This test proves data written in one
    "request" (one save() call) is visible in a completely separate one
    (a fresh repository instance, a fresh load() call), which is the
    actual behavior a running server depends on across HTTP requests.
    """
    repo_a = SqlVaultRepository(session_factory)
    repo_a.save(_sample_meta())

    repo_b = SqlVaultRepository(session_factory)
    assert repo_b.load() is not None
