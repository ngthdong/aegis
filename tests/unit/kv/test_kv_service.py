from __future__ import annotations

import pytest
from sqlalchemy.orm import sessionmaker

from aegis.audit.logger import AuditLogger
from aegis.audit.repository import InMemoryAuditRepository
from aegis.auth.session_service import Principal
from aegis.authz.service import AuthzService, PermissionDenied
from aegis.common.clock import FakeClock
from aegis.common.metrics import create_metrics
from aegis.core.repository import InMemoryVaultRepository
from aegis.core.service import VaultService
from aegis.kv.repository import InMemorySecretRepository, SqlSecretRepository
from aegis.kv.service import (
    KvService,
    SecretCorrupted,
    SecretNotFound,
    SecretVersionNotFound,
)
from aegis.storage.db import create_memory_engine, get_sessionmaker
from aegis.storage.models import Base, SecretVersionRow

ALICE = Principal(user_id="user-alice", username="alice")
BOB = Principal(user_id="user-bob", username="bob")


@pytest.fixture
def unsealed_vault() -> VaultService:
    vault = VaultService(InMemoryVaultRepository())
    vault.initialize("correct horse battery staple")
    vault.unseal("correct horse battery staple")
    return vault


@pytest.fixture
def session_factory() -> sessionmaker:
    engine = create_memory_engine()
    Base.metadata.create_all(engine)
    return get_sessionmaker(engine)


@pytest.fixture(params=["in_memory", "sql"])
def kv(request, unsealed_vault: VaultService, session_factory: sessionmaker) -> KvService:
    repo = (
        InMemorySecretRepository()
        if request.param == "in_memory"
        else SqlSecretRepository(session_factory)
    )
    return KvService(
        repo,
        AuthzService(),
        unsealed_vault,
        FakeClock(),
        AuditLogger(InMemoryAuditRepository(), FakeClock(), create_metrics()),
    )


def test_first_write_creates_version_1(kv: KvService):
    version = kv.write(ALICE, "db/password", {"value": "v1"})
    assert version == 1
    assert kv.read(ALICE, "db/password") == {"value": "v1"}


def test_second_write_creates_version_2_and_becomes_current(kv: KvService):
    kv.write(ALICE, "db/password", {"value": "v1"})
    version = kv.write(ALICE, "db/password", {"value": "v2"})

    assert version == 2
    assert kv.read(ALICE, "db/password") == {"value": "v2"}


def test_old_version_remains_readable_after_overwrite(kv: KvService):
    kv.write(ALICE, "db/password", {"value": "v1"})
    kv.write(ALICE, "db/password", {"value": "v2"})
    kv.write(ALICE, "db/password", {"value": "v3"})

    assert kv.read(ALICE, "db/password", version=1) == {"value": "v1"}
    assert kv.read(ALICE, "db/password", version=2) == {"value": "v2"}
    assert kv.read(ALICE, "db/password", version=3) == {"value": "v3"}
    assert kv.read(ALICE, "db/password") == {"value": "v3"}


def test_reading_a_nonexistent_version_number_raises_version_not_found(kv: KvService):
    kv.write(ALICE, "db/password", {"value": "v1"})
    with pytest.raises(SecretVersionNotFound):
        kv.read(ALICE, "db/password", version=99)


def test_version_not_found_is_distinct_from_secret_not_found(kv: KvService):
    with pytest.raises(SecretNotFound):
        kv.read(ALICE, "never/written", version=1)


def test_non_owner_cannot_overwrite_an_existing_path(kv: KvService):
    kv.write(ALICE, "db/password", {"value": "v1"})
    with pytest.raises(PermissionDenied):
        kv.write(BOB, "db/password", {"value": "hijacked"})
    assert kv.read(ALICE, "db/password") == {"value": "v1"}


def test_non_owner_cannot_read_any_version(kv: KvService):
    kv.write(ALICE, "db/password", {"value": "v1"})
    kv.write(ALICE, "db/password", {"value": "v2"})
    with pytest.raises(PermissionDenied):
        kv.read(BOB, "db/password", version=1)


def test_delete_removes_every_version_not_just_current(kv: KvService):
    kv.write(ALICE, "db/password", {"value": "v1"})
    kv.write(ALICE, "db/password", {"value": "v2"})

    kv.delete(ALICE, "db/password")

    with pytest.raises(SecretNotFound):
        kv.read(ALICE, "db/password")
    with pytest.raises(SecretNotFound):
        kv.read(ALICE, "db/password", version=1)


def test_write_after_delete_starts_a_fresh_version_1(kv: KvService):
    kv.write(ALICE, "db/password", {"value": "v1"})
    kv.write(ALICE, "db/password", {"value": "v2"})
    kv.delete(ALICE, "db/password")

    new_version = kv.write(ALICE, "db/password", {"value": "brand new"})

    assert new_version == 1
    assert kv.read(ALICE, "db/password") == {"value": "brand new"}


def test_version_swap_between_two_versions_of_the_same_secret_is_detected(
    unsealed_vault: VaultService,
):
    engine = create_memory_engine()
    Base.metadata.create_all(engine)
    session_factory = get_sessionmaker(engine)
    repo = SqlSecretRepository(session_factory)
    audit = AuditLogger(InMemoryAuditRepository(), FakeClock(), create_metrics())
    kv = KvService(repo, AuthzService(), unsealed_vault, FakeClock(), audit)

    kv.write(ALICE, "db/password", {"value": "version one"})
    kv.write(ALICE, "db/password", {"value": "version two"})

    secret = repo.get_by_path("db/password")

    with session_factory() as session:
        from sqlalchemy import select

        v1_row = session.execute(
            select(SecretVersionRow).where(
                SecretVersionRow.secret_id == secret.id, SecretVersionRow.version == 1
            )
        ).scalar_one()
        v2_row = session.execute(
            select(SecretVersionRow).where(
                SecretVersionRow.secret_id == secret.id, SecretVersionRow.version == 2
            )
        ).scalar_one()

        # Swap version 1's and version 2's ciphertext/nonce between rows.
        v1_nonce, v1_ct = v1_row.nonce, v1_row.ciphertext
        v1_row.nonce, v1_row.ciphertext = v2_row.nonce, v2_row.ciphertext
        v2_row.nonce, v2_row.ciphertext = v1_nonce, v1_ct
        session.commit()

    with pytest.raises(SecretCorrupted):
        kv.read(ALICE, "db/password", version=1)
    with pytest.raises(SecretCorrupted):
        kv.read(ALICE, "db/password", version=2)


def test_tampering_with_ciphertext_directly_is_still_detected_sql(unsealed_vault: VaultService):
    engine = create_memory_engine()
    Base.metadata.create_all(engine)
    session_factory = get_sessionmaker(engine)
    repo = SqlSecretRepository(session_factory)
    audit = AuditLogger(InMemoryAuditRepository(), FakeClock(), create_metrics())
    kv = KvService(repo, AuthzService(), unsealed_vault, FakeClock(), audit)

    kv.write(ALICE, "db/password", {"value": "hunter2"})
    secret = repo.get_by_path("db/password")

    with session_factory() as session:
        from sqlalchemy import select

        row = session.execute(
            select(SecretVersionRow).where(
                SecretVersionRow.secret_id == secret.id, SecretVersionRow.version == 1
            )
        ).scalar_one()
        tampered = bytearray(row.ciphertext)
        tampered[0] ^= 0xFF
        row.ciphertext = bytes(tampered)
        session.commit()

    with pytest.raises(SecretCorrupted):
        kv.read(ALICE, "db/password", version=1)


def test_deleting_a_secret_actually_removes_version_rows_from_the_database(
    unsealed_vault: VaultService,
):
    engine = create_memory_engine()
    Base.metadata.create_all(engine)
    session_factory = get_sessionmaker(engine)
    repo = SqlSecretRepository(session_factory)
    audit = AuditLogger(InMemoryAuditRepository(), FakeClock(), create_metrics())
    kv = KvService(repo, AuthzService(), unsealed_vault, FakeClock(), audit)

    kv.write(ALICE, "db/password", {"value": "v1"})
    kv.write(ALICE, "db/password", {"value": "v2"})
    kv.delete(ALICE, "db/password")

    with session_factory() as session:
        from sqlalchemy import select

        remaining = session.execute(select(SecretVersionRow)).scalars().all()
        assert remaining == []


def test_audit_events_include_the_version_number(kv: KvService):
    audit_repo = InMemoryAuditRepository()
    kv._audit = AuditLogger(audit_repo, FakeClock(), create_metrics())  # type: ignore[attr-defined]

    kv.write(ALICE, "audit/path", {"value": "v1"})
    kv.write(ALICE, "audit/path", {"value": "v2"})
    kv.read(ALICE, "audit/path", version=1)

    versions_recorded = [e.metadata.get("version") for e in audit_repo.events]
    assert versions_recorded == [1, 2, 1]
