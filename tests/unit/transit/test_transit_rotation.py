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
from aegis.transit.models import pack_version_tag
from aegis.transit.repository import InMemoryTransitKeyRepository, SqlTransitKeyRepository
from aegis.transit.service import (
    TransitDecryptionFailed,
    TransitKeyDestroyed,
    TransitKeyVersionNotFound,
    TransitService,
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


def test_rotate_returns_the_new_version_number(transit: TransitService):
    transit.create_key(ALICE, "app-1")
    new_version = transit.rotate_key(ALICE, "app-1")
    assert new_version == 2


def test_encrypt_always_uses_the_latest_version(transit: TransitService):
    transit.create_key(ALICE, "app-1")
    transit.rotate_key(ALICE, "app-1")
    transit.rotate_key(ALICE, "app-1")

    ciphertext = transit.encrypt(ALICE, "app-1", b"data")
    raw = base64.b64decode(ciphertext)
    assert raw[:4] == pack_version_tag(3)


def test_decrypt_works_on_data_encrypted_before_a_rotation(transit: TransitService):
    transit.create_key(ALICE, "app-1")
    old_ciphertext = transit.encrypt(ALICE, "app-1", b"secret from before rotation")

    transit.rotate_key(ALICE, "app-1")
    transit.rotate_key(ALICE, "app-1")

    plaintext = transit.decrypt(ALICE, "app-1", old_ciphertext)
    assert plaintext == b"secret from before rotation"


def test_new_ciphertext_after_rotation_uses_new_version_and_old_ciphertext_still_works(
    transit: TransitService,
):
    transit.create_key(ALICE, "app-1")
    ct_v1 = transit.encrypt(ALICE, "app-1", b"v1 data")

    transit.rotate_key(ALICE, "app-1")
    ct_v2 = transit.encrypt(ALICE, "app-1", b"v2 data")

    assert transit.decrypt(ALICE, "app-1", ct_v1) == b"v1 data"
    assert transit.decrypt(ALICE, "app-1", ct_v2) == b"v2 data"


def test_only_owner_can_rotate(transit: TransitService):
    transit.create_key(ALICE, "app-1")
    with pytest.raises(PermissionDenied):
        transit.rotate_key(BOB, "app-1")


def test_cannot_rotate_a_destroyed_key(transit: TransitService):
    transit.create_key(ALICE, "app-1")
    transit.destroy_key(ALICE, "app-1")
    with pytest.raises(TransitKeyDestroyed):
        transit.rotate_key(ALICE, "app-1")


def test_decrypt_of_a_destroyed_key_raises_destroyed_not_generic_failure(
    transit: TransitService,
):
    transit.create_key(ALICE, "app-1")
    ciphertext = transit.encrypt(ALICE, "app-1", b"data")
    transit.destroy_key(ALICE, "app-1")

    with pytest.raises(TransitKeyDestroyed):
        transit.decrypt(ALICE, "app-1", ciphertext)


def test_rotating_repeatedly_preserves_every_prior_version(transit: TransitService):
    transit.create_key(ALICE, "app-1")
    ciphertexts = [transit.encrypt(ALICE, "app-1", b"data-v1")]
    for i in range(2, 6):
        transit.rotate_key(ALICE, "app-1")
        ciphertexts.append(transit.encrypt(ALICE, "app-1", f"data-v{i}".encode()))

    for i, ct in enumerate(ciphertexts, start=1):
        assert transit.decrypt(ALICE, "app-1", ct) == f"data-v{i}".encode()


def test_signing_key_rotation_old_signature_still_verifies(transit: TransitService):
    transit.create_key(ALICE, "signer-1", key_type="asymmetric_sign")
    old_signature = transit.sign(ALICE, "signer-1", b"message signed before rotation")

    transit.rotate_key(ALICE, "signer-1")

    result = transit.verify(ALICE, "signer-1", b"message signed before rotation", old_signature)
    assert result.signature_valid is True


def test_signing_uses_latest_version_after_rotation(transit: TransitService):
    transit.create_key(ALICE, "signer-1", key_type="asymmetric_sign")
    transit.rotate_key(ALICE, "signer-1")

    new_signature = transit.sign(ALICE, "signer-1", b"new message")
    raw = base64.b64decode(new_signature)
    assert raw[:4] == pack_version_tag(2)


def test_verify_rejects_a_version_that_never_existed(transit: TransitService):
    transit.create_key(ALICE, "signer-1", key_type="asymmetric_sign")
    signature = transit.sign(ALICE, "signer-1", b"message")

    raw = bytearray(base64.b64decode(signature))
    raw[0:4] = pack_version_tag(99)
    tampered_signature = base64.b64encode(bytes(raw)).decode("ascii")

    with pytest.raises(TransitKeyVersionNotFound):
        transit.verify(ALICE, "signer-1", b"message", tampered_signature)


def test_signature_from_one_version_does_not_verify_under_a_different_versions_public_key(
    transit: TransitService,
):
    transit.create_key(ALICE, "signer-1", key_type="asymmetric_sign")
    v1_signature = transit.sign(ALICE, "signer-1", b"message")
    transit.rotate_key(ALICE, "signer-1")

    raw = bytearray(base64.b64decode(v1_signature))
    raw[0:4] = pack_version_tag(2)
    relabeled = base64.b64encode(bytes(raw)).decode("ascii")

    result = transit.verify(ALICE, "signer-1", b"message", relabeled)
    assert result.signature_valid is False


def test_legacy_unversioned_ciphertext_still_decrypts(transit: TransitService):
    transit.create_key(ALICE, "app-1")

    from aegis.crypto.aead import encrypt as aead_encrypt

    key = transit._repository.get_by_name("app-1")  # type: ignore[attr-defined]
    version_row = transit._repository.get_version(key.id, 1)  # type: ignore[attr-defined]
    raw_key = transit._unwrap(key, version_row, 1)  # type: ignore[attr-defined]

    legacy_envelope = aead_encrypt(raw_key, b"pre-rotation data")
    legacy_blob = base64.b64encode(legacy_envelope.nonce + legacy_envelope.ciphertext).decode(
        "ascii"
    )

    plaintext = transit.decrypt(ALICE, "app-1", legacy_blob)
    assert plaintext == b"pre-rotation data"


def test_legacy_signature_still_verifies(transit: TransitService):
    transit.create_key(ALICE, "signer-1", key_type="asymmetric_sign")

    from aegis.crypto.signing import sign as ed25519_sign

    key = transit._repository.get_by_name("signer-1")  # type: ignore[attr-defined]
    version_row = transit._repository.get_version(key.id, 1)  # type: ignore[attr-defined]
    private_key_bytes = transit._unwrap(key, version_row, 1)  # type: ignore[attr-defined]

    legacy_signature = base64.b64encode(ed25519_sign(private_key_bytes, b"legacy message")).decode(
        "ascii"
    )

    result = transit.verify(ALICE, "signer-1", b"legacy message", legacy_signature)
    assert result.signature_valid is True


def test_garbage_ciphertext_fails_both_versioned_and_legacy_interpretation(
    transit: TransitService,
):
    transit.create_key(ALICE, "app-1")
    with pytest.raises(TransitDecryptionFailed):
        transit.decrypt(ALICE, "app-1", base64.b64encode(b"complete garbage bytes").decode())


def test_rotate_produces_a_success_audit_event_with_new_version(
    transit: TransitService, audit_repo: InMemoryAuditRepository
):
    transit.create_key(ALICE, "app-1")
    audit_repo.events.clear()

    transit.rotate_key(ALICE, "app-1")

    assert len(audit_repo.events) == 1
    event = audit_repo.events[0]
    assert event.action == "transit.rotate"
    assert event.outcome == "success"
    assert event.metadata["new_version"] == 2


def test_rotation_round_trip_against_real_sqlite(unsealed_vault: VaultService):
    from sqlalchemy.orm import sessionmaker

    from aegis.storage.db import create_memory_engine, get_sessionmaker
    from aegis.storage.models import Base

    engine = create_memory_engine()
    Base.metadata.create_all(engine)
    session_factory: sessionmaker = get_sessionmaker(engine)
    repo = SqlTransitKeyRepository(session_factory)
    audit = AuditLogger(InMemoryAuditRepository(), FakeClock(), create_metrics())
    transit = TransitService(repo, AuthzService(), unsealed_vault, FakeClock(), audit)

    transit.create_key(ALICE, "app-1")
    ct_v1 = transit.encrypt(ALICE, "app-1", b"version one data")
    transit.rotate_key(ALICE, "app-1")
    ct_v2 = transit.encrypt(ALICE, "app-1", b"version two data")

    assert transit.decrypt(ALICE, "app-1", ct_v1) == b"version one data"
    assert transit.decrypt(ALICE, "app-1", ct_v2) == b"version two data"
