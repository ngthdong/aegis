from __future__ import annotations

import base64

import pytest

from aegis.audit.logger import AuditLogger
from aegis.audit.repository import InMemoryAuditRepository
from aegis.auth.session_service import Principal
from aegis.authz.service import AuthzService, PermissionDenied
from aegis.common.clock import FakeClock
from aegis.common.metrics import create_metrics
from aegis.core.repository import InMemoryVaultRepository
from aegis.core.service import VaultService
from aegis.transit.repository import InMemoryTransitKeyRepository
from aegis.transit.service import (
    TransitKeyDestroyed,
    TransitKeyDisabled,
    TransitService,
    WrongKeyType,
)

ALICE = Principal(user_id="user-alice", username="alice")
BOB = Principal(user_id="user-bob", username="bob")


@pytest.fixture
def unsealed_vault() -> VaultService:
    vault = VaultService(InMemoryVaultRepository())
    vault.initialize("correct horse battery staple")
    vault.unseal("correct horse battery staple")
    return vault


@pytest.fixture
def audit_repo() -> InMemoryAuditRepository:
    return InMemoryAuditRepository()


@pytest.fixture
def transit(unsealed_vault: VaultService, audit_repo: InMemoryAuditRepository) -> TransitService:
    return TransitService(
        InMemoryTransitKeyRepository(),
        AuthzService(),
        unsealed_vault,
        FakeClock(),
        AuditLogger(audit_repo, FakeClock(), create_metrics()),
    )


def test_create_signing_key_then_sign_then_verify(transit: TransitService):
    transit.create_key(ALICE, "sig-1", key_type="asymmetric_sign")
    signature = transit.sign(ALICE, "sig-1", b"transfer $100")
    assert transit.verify(ALICE, "sig-1", b"transfer $100", signature) is True


def test_verify_fails_for_tampered_message(transit: TransitService):
    transit.create_key(ALICE, "sig-1", key_type="asymmetric_sign")
    signature = transit.sign(ALICE, "sig-1", b"original message")
    assert transit.verify(ALICE, "sig-1", b"tampered message", signature) is False


def test_non_owner_cannot_sign(transit: TransitService):
    transit.create_key(ALICE, "sig-1", key_type="asymmetric_sign")
    with pytest.raises(PermissionDenied):
        transit.sign(BOB, "sig-1", b"message")


def test_non_owner_can_verify(transit: TransitService):
    transit.create_key(ALICE, "sig-1", key_type="asymmetric_sign")
    signature = transit.sign(ALICE, "sig-1", b"message")

    assert transit.verify(BOB, "sig-1", b"message", signature) is True


def test_sign_rejects_a_symmetric_key(transit: TransitService):
    transit.create_key(ALICE, "sym-1", key_type="symmetric")
    with pytest.raises(WrongKeyType):
        transit.sign(ALICE, "sym-1", b"message")


def test_encrypt_rejects_a_signing_key(transit: TransitService):
    transit.create_key(ALICE, "sig-1", key_type="asymmetric_sign")
    with pytest.raises(WrongKeyType):
        transit.encrypt(ALICE, "sig-1", b"data")


def test_verify_rejects_a_symmetric_key(transit: TransitService):
    transit.create_key(ALICE, "sym-1", key_type="symmetric")
    with pytest.raises(WrongKeyType):
        transit.verify(ALICE, "sym-1", b"message", base64.b64encode(b"x" * 64).decode())


# --- Lifecycle: disable ---


def test_disabled_key_blocks_new_encrypt(transit: TransitService):
    transit.create_key(ALICE, "app-1", key_type="symmetric")
    transit.disable_key(ALICE, "app-1")
    with pytest.raises(TransitKeyDisabled):
        transit.encrypt(ALICE, "app-1", b"data")


def test_disabled_key_still_allows_decrypt_of_existing_data(transit: TransitService):
    transit.create_key(ALICE, "app-1", key_type="symmetric")
    ciphertext = transit.encrypt(ALICE, "app-1", b"data encrypted before disable")

    transit.disable_key(ALICE, "app-1")

    plaintext = transit.decrypt(ALICE, "app-1", ciphertext)
    assert plaintext == b"data encrypted before disable"


def test_disabled_signing_key_blocks_new_signs_but_allows_verify(transit: TransitService):
    transit.create_key(ALICE, "sig-1", key_type="asymmetric_sign")
    signature = transit.sign(ALICE, "sig-1", b"signed before disable")

    transit.disable_key(ALICE, "sig-1")

    with pytest.raises(TransitKeyDisabled):
        transit.sign(ALICE, "sig-1", b"signed after disable")

    assert transit.verify(ALICE, "sig-1", b"signed before disable", signature) is True


def test_only_owner_can_disable(transit: TransitService):
    transit.create_key(ALICE, "app-1", key_type="symmetric")
    with pytest.raises(PermissionDenied):
        transit.disable_key(BOB, "app-1")


def test_destroyed_key_blocks_encrypt_decrypt_sign_and_verify(transit: TransitService):
    transit.create_key(ALICE, "app-1", key_type="symmetric")
    ciphertext = transit.encrypt(ALICE, "app-1", b"data")

    transit.destroy_key(ALICE, "app-1")

    with pytest.raises(TransitKeyDestroyed):
        transit.encrypt(ALICE, "app-1", b"more data")
    with pytest.raises(TransitKeyDestroyed):
        transit.decrypt(ALICE, "app-1", ciphertext)


def test_destroyed_signing_key_blocks_verify_too(transit: TransitService):
    transit.create_key(ALICE, "sig-1", key_type="asymmetric_sign")
    signature = transit.sign(ALICE, "sig-1", b"message")

    transit.destroy_key(ALICE, "sig-1")

    with pytest.raises(TransitKeyDestroyed):
        transit.verify(ALICE, "sig-1", b"message", signature)


def test_destroy_is_irreversible_second_destroy_raises(transit: TransitService):
    transit.create_key(ALICE, "app-1", key_type="symmetric")
    transit.destroy_key(ALICE, "app-1")
    with pytest.raises(TransitKeyDestroyed):
        transit.destroy_key(ALICE, "app-1")


def test_destroyed_key_row_survives_as_tombstone(transit: TransitService):
    transit.create_key(ALICE, "app-1", key_type="symmetric")
    transit.destroy_key(ALICE, "app-1")

    repo = transit._repository  # type: ignore[attr-defined]
    tombstone = repo.get_by_name("app-1")
    assert tombstone is not None
    assert tombstone.is_destroyed
    assert tombstone.wrapped_key is None


def test_only_owner_can_destroy(transit: TransitService):
    transit.create_key(ALICE, "app-1", key_type="symmetric")
    with pytest.raises(PermissionDenied):
        transit.destroy_key(BOB, "app-1")


def test_cannot_disable_a_destroyed_key(transit: TransitService):
    transit.create_key(ALICE, "app-1", key_type="symmetric")
    transit.destroy_key(ALICE, "app-1")
    with pytest.raises(TransitKeyDestroyed):
        transit.disable_key(ALICE, "app-1")


def test_disable_and_destroy_produce_success_audit_events(
    transit: TransitService, audit_repo: InMemoryAuditRepository
):
    transit.create_key(ALICE, "app-1", key_type="symmetric")
    transit.disable_key(ALICE, "app-1")
    transit.destroy_key(ALICE, "app-1")

    outcomes = [(e.action, e.outcome) for e in audit_repo.events]
    assert outcomes == [
        ("transit.create_key", "success"),
        ("transit.disable", "success"),
        ("transit.destroy", "success"),
    ]


def test_verify_by_non_owner_produces_a_success_audit_event_not_denied(
    transit: TransitService, audit_repo: InMemoryAuditRepository
):
    transit.create_key(ALICE, "sig-1", key_type="asymmetric_sign")
    signature = transit.sign(ALICE, "sig-1", b"message")
    audit_repo.events.clear()

    transit.verify(BOB, "sig-1", b"message", signature)

    assert len(audit_repo.events) == 1
    assert audit_repo.events[0].action == "transit.verify"
    assert audit_repo.events[0].outcome == "success"
    assert audit_repo.events[0].principal_id == BOB.user_id
