from __future__ import annotations

import pytest

from aegis.audit.logger import AuditLogger
from aegis.audit.repository import InMemoryAuditRepository
from aegis.auth.session_service import Principal
from aegis.authz.service import AuthzService, PermissionDenied
from aegis.common.clock import FakeClock
from aegis.core.repository import InMemoryVaultRepository
from aegis.core.service import VaultService
from aegis.kv.repository import InMemorySecretRepository
from aegis.kv.service import KvService, SecretCorrupted, SecretNotFound

ALICE = Principal(user_id="user-alice", username="alice")
BOB = Principal(user_id="user-bob", username="bob")


@pytest.fixture
def audit_repo() -> InMemoryAuditRepository:
    return InMemoryAuditRepository()


@pytest.fixture
def unsealed_vault() -> VaultService:
    vault = VaultService(InMemoryVaultRepository())
    vault.initialize("correct horse battery staple")
    vault.unseal("correct horse battery staple")
    return vault


@pytest.fixture
def kv(unsealed_vault: VaultService, audit_repo: InMemoryAuditRepository) -> KvService:
    return KvService(
        InMemorySecretRepository(),
        AuthzService(),
        unsealed_vault,
        FakeClock(),
        AuditLogger(audit_repo, FakeClock()),
    )


def test_write_then_read_round_trips(kv: KvService):
    kv.write(ALICE, "db/password", {"value": "hunter2"})
    assert kv.read(ALICE, "db/password") == {"value": "hunter2"}


def test_read_nonexistent_path_raises_not_found(kv: KvService):
    with pytest.raises(SecretNotFound):
        kv.read(ALICE, "does/not/exist")


def test_non_owner_cannot_read(kv: KvService):
    kv.write(ALICE, "secret/path", {"value": "x"})
    with pytest.raises(PermissionDenied):
        kv.read(BOB, "secret/path")


def test_non_owner_cannot_overwrite(kv: KvService):
    kv.write(ALICE, "secret/path", {"value": "original"})
    with pytest.raises(PermissionDenied):
        kv.write(BOB, "secret/path", {"value": "overwritten-by-bob"})
    assert kv.read(ALICE, "secret/path") == {"value": "original"}


def test_non_owner_cannot_delete(kv: KvService):
    kv.write(ALICE, "secret/path", {"value": "x"})
    with pytest.raises(PermissionDenied):
        kv.delete(BOB, "secret/path")
    kv.read(ALICE, "secret/path")  # must still exist


def test_owner_can_overwrite_and_new_value_is_returned(kv: KvService):
    kv.write(ALICE, "secret/path", {"value": "v1"})
    kv.write(ALICE, "secret/path", {"value": "v2"})
    assert kv.read(ALICE, "secret/path") == {"value": "v2"}


def test_owner_can_delete_then_path_is_gone(kv: KvService):
    kv.write(ALICE, "secret/path", {"value": "x"})
    kv.delete(ALICE, "secret/path")
    with pytest.raises(SecretNotFound):
        kv.read(ALICE, "secret/path")


def test_tampered_ciphertext_raises_secret_corrupted_not_a_crash(kv: KvService):
    kv.write(ALICE, "secret/path", {"value": "hunter2"})

    from dataclasses import replace

    from aegis.crypto.aead import Envelope

    repo = kv._repository  # type: ignore[attr-defined]
    stored = repo.get_by_path("secret/path")
    tampered_ciphertext = bytearray(stored.envelope.ciphertext)
    tampered_ciphertext[0] ^= 0xFF
    tampered_envelope = Envelope(nonce=stored.envelope.nonce, ciphertext=bytes(tampered_ciphertext))
    repo.save(replace(stored, envelope=tampered_envelope))

    with pytest.raises(SecretCorrupted):
        kv.read(ALICE, "secret/path")


def test_reassigning_owner_id_without_touching_ciphertext_is_detected(kv: KvService):
    kv.write(ALICE, "secret/path", {"value": "hunter2"})

    from dataclasses import replace

    repo = kv._repository  # type: ignore[attr-defined]
    stored = repo.get_by_path("secret/path")
    repo.save(replace(stored, owner_id="attacker-id"))

    fake_owner = Principal(user_id="attacker-id", username="attacker")
    with pytest.raises(SecretCorrupted):
        kv.read(fake_owner, "secret/path")


def test_write_requires_unsealed_vault(unsealed_vault: VaultService):
    from aegis.core.service import VaultNotInitialized

    unsealed_vault.seal()
    kv = KvService(
        InMemorySecretRepository(),
        AuthzService(),
        unsealed_vault,
        FakeClock(),
        AuditLogger(InMemoryAuditRepository(), FakeClock()),
    )
    with pytest.raises(VaultNotInitialized):
        kv.write(ALICE, "secret/path", {"value": "x"})


def test_denied_overwrite_produces_a_denied_audit_event_not_a_success(
    kv: KvService, audit_repo: InMemoryAuditRepository
):
    kv.write(ALICE, "audit/path", {"value": "x"})
    audit_repo.events.clear()

    with pytest.raises(PermissionDenied):
        kv.write(BOB, "audit/path", {"value": "y"})

    assert len(audit_repo.events) == 1
    assert audit_repo.events[0].outcome == "denied"
    assert audit_repo.events[0].principal_id == BOB.user_id


def test_full_lifecycle_produces_events_in_the_expected_order(
    kv: KvService, audit_repo: InMemoryAuditRepository
):
    kv.write(ALICE, "lifecycle/path", {"value": "x"})
    kv.read(ALICE, "lifecycle/path")
    kv.delete(ALICE, "lifecycle/path")
    with pytest.raises(SecretNotFound):
        kv.read(ALICE, "lifecycle/path")

    outcomes = [(e.action, e.outcome) for e in audit_repo.events]
    assert outcomes == [
        ("kv.write", "success"),
        ("kv.read", "success"),
        ("kv.delete", "success"),
        ("kv.read", "error"),
    ]


def test_audit_fires_even_when_service_called_directly_not_through_http(
    kv: KvService, audit_repo: InMemoryAuditRepository
):
    kv.write(ALICE, "direct/call", {"value": "x"})
    assert len(audit_repo.events) == 1
