from __future__ import annotations

import pytest

from aegis.audit.logger import AuditLogger
from aegis.audit.repository import InMemoryAuditRepository
from aegis.auth.session_service import Principal
from aegis.authz.service import AuthzService, PermissionDenied
from aegis.common.clock import FakeClock
from aegis.common.metrics import create_metrics
from aegis.core.repository import InMemoryVaultRepository
from aegis.core.service import VaultService
from aegis.transit.models import DIGEST_LENGTH_BYTES
from aegis.transit.repository import InMemoryTransitKeyRepository
from aegis.transit.service import (
    InvalidMessageType,
    TransitDecryptionFailed,
    TransitKeyAlreadyExists,
    TransitKeyNotFound,
    TransitService,
    VerifyResult,
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


def test_create_then_encrypt_then_decrypt_round_trips(transit: TransitService):
    transit.create_key(ALICE, "app-1")
    ciphertext = transit.encrypt(ALICE, "app-1", b"hello world")
    plaintext = transit.decrypt(ALICE, "app-1", ciphertext)
    assert plaintext == b"hello world"


def test_ciphertext_is_not_the_plaintext(transit: TransitService):
    transit.create_key(ALICE, "app-1")
    ciphertext = transit.encrypt(ALICE, "app-1", b"hello world")
    assert b"hello world" not in ciphertext.encode()


def test_two_encryptions_of_same_plaintext_differ(transit: TransitService):
    transit.create_key(ALICE, "app-1")
    ct1 = transit.encrypt(ALICE, "app-1", b"same plaintext")
    ct2 = transit.encrypt(ALICE, "app-1", b"same plaintext")
    assert ct1 != ct2


def test_create_key_rejects_duplicate_name(transit: TransitService):
    transit.create_key(ALICE, "app-1")
    with pytest.raises(TransitKeyAlreadyExists):
        transit.create_key(ALICE, "app-1")


def test_create_key_rejects_duplicate_name_even_for_different_owner(transit: TransitService):
    transit.create_key(ALICE, "app-1")
    with pytest.raises(TransitKeyAlreadyExists):
        transit.create_key(BOB, "app-1")


def test_non_owner_cannot_encrypt_under_someone_elses_key(transit: TransitService):
    transit.create_key(ALICE, "app-1")
    with pytest.raises(PermissionDenied):
        transit.encrypt(BOB, "app-1", b"data")


def test_non_owner_cannot_decrypt_under_someone_elses_key(transit: TransitService):
    transit.create_key(ALICE, "app-1")
    ciphertext = transit.encrypt(ALICE, "app-1", b"data")
    with pytest.raises(PermissionDenied):
        transit.decrypt(BOB, "app-1", ciphertext)


def test_encrypt_under_nonexistent_key_raises_not_found(transit: TransitService):
    with pytest.raises(TransitKeyNotFound):
        transit.encrypt(ALICE, "does-not-exist", b"data")


def test_tampered_ciphertext_raises_transit_decryption_failed_not_a_crash(
    transit: TransitService,
):
    transit.create_key(ALICE, "app-1")
    ciphertext = transit.encrypt(ALICE, "app-1", b"hello world")

    import base64

    raw = bytearray(base64.b64decode(ciphertext))
    raw[-1] ^= 0xFF  # flip the last byte
    tampered = base64.b64encode(bytes(raw)).decode("ascii")

    with pytest.raises(TransitDecryptionFailed):
        transit.decrypt(ALICE, "app-1", tampered)


def test_ciphertext_from_one_key_cannot_be_decrypted_under_a_different_key(
    transit: TransitService,
):
    transit.create_key(ALICE, "key-a")
    transit.create_key(ALICE, "key-b")

    ciphertext_under_a = transit.encrypt(ALICE, "key-a", b"secret data")

    with pytest.raises(TransitDecryptionFailed):
        transit.decrypt(ALICE, "key-b", ciphertext_under_a)


def test_wrapped_key_tamper_is_detected_on_next_use(transit: TransitService):
    transit.create_key(ALICE, "app-1")

    from dataclasses import replace

    from aegis.crypto.aead import DecryptionError, Envelope

    repo = transit._repository  # type: ignore[attr-defined]
    stored = repo.get_by_name("app-1")
    tampered_ciphertext = bytearray(stored.wrapped_key.ciphertext)
    tampered_ciphertext[0] ^= 0xFF
    tampered_envelope = Envelope(
        nonce=stored.wrapped_key.nonce, ciphertext=bytes(tampered_ciphertext)
    )
    repo.save(replace(stored, wrapped_key=tampered_envelope))

    with pytest.raises(DecryptionError):
        transit.encrypt(ALICE, "app-1", b"data")


def test_create_key_requires_unsealed_vault(
    unsealed_vault: VaultService, audit_repo: InMemoryAuditRepository
):
    from aegis.core.service import VaultNotInitialized

    unsealed_vault.seal()
    transit = TransitService(
        InMemoryTransitKeyRepository(),
        AuthzService(),
        unsealed_vault,
        FakeClock(),
        AuditLogger(audit_repo, FakeClock(), create_metrics()),
    )
    with pytest.raises(VaultNotInitialized):
        transit.create_key(ALICE, "app-1")


def test_successful_operations_produce_success_audit_events(
    transit: TransitService, audit_repo: InMemoryAuditRepository
):
    transit.create_key(ALICE, "app-1")
    transit.encrypt(ALICE, "app-1", b"data")

    outcomes = [(e.action, e.outcome) for e in audit_repo.events]
    assert outcomes == [
        ("transit.create_key", "success"),
        ("transit.encrypt", "success"),
    ]


def test_denied_encrypt_produces_denied_audit_event(
    transit: TransitService, audit_repo: InMemoryAuditRepository
):
    transit.create_key(ALICE, "app-1")
    audit_repo.events.clear()

    with pytest.raises(PermissionDenied):
        transit.encrypt(BOB, "app-1", b"data")

    assert len(audit_repo.events) == 1
    assert audit_repo.events[0].outcome == "denied"
    assert audit_repo.events[0].principal_id == BOB.user_id


def test_verify_returns_structured_result_not_a_bare_bool(transit: TransitService):
    transit.create_key(ALICE, "doc-signer", key_type="asymmetric_sign")
    signature = transit.sign(ALICE, "doc-signer", b"message")

    result = transit.verify(ALICE, "doc-signer", b"message", signature)

    assert isinstance(result, VerifyResult)
    assert result.key_name == "doc-signer"
    assert result.signature_valid is True
    assert result.signing_algorithm == "Ed25519"


def test_verify_result_reports_false_for_tampered_message_not_an_exception(
    transit: TransitService,
):
    transit.create_key(ALICE, "doc-signer", key_type="asymmetric_sign")
    signature = transit.sign(ALICE, "doc-signer", b"original")

    result = transit.verify(ALICE, "doc-signer", b"tampered", signature)

    assert result.signature_valid is False
    assert result.key_name == "doc-signer"
    assert result.signing_algorithm == "Ed25519"


def test_raw_message_type_is_the_default_and_matches_prior_behavior(transit: TransitService):
    transit.create_key(ALICE, "doc-signer", key_type="asymmetric_sign")
    signature = transit.sign(ALICE, "doc-signer", b"a normal document")
    result = transit.verify(ALICE, "doc-signer", b"a normal document", signature)
    assert result.signature_valid is True


def test_digest_mode_requires_hash_algorithm(transit: TransitService):
    transit.create_key(ALICE, "doc-signer", key_type="asymmetric_sign")
    digest = b"\x00" * 32

    with pytest.raises(InvalidMessageType, match="hash_algorithm is required"):
        transit.sign(ALICE, "doc-signer", digest, message_type="DIGEST")


def test_raw_mode_rejects_a_hash_algorithm_being_supplied(transit: TransitService):
    transit.create_key(ALICE, "doc-signer", key_type="asymmetric_sign")

    with pytest.raises(InvalidMessageType, match="must not be supplied"):
        transit.sign(ALICE, "doc-signer", b"a message", message_type="RAW", hash_algorithm="SHA256")


def test_digest_mode_rejects_wrong_length_for_claimed_algorithm(transit: TransitService):
    transit.create_key(ALICE, "doc-signer", key_type="asymmetric_sign")
    wrong_length_digest = b"\x00" * 20

    with pytest.raises(InvalidMessageType, match="does not match expected"):
        transit.sign(
            ALICE,
            "doc-signer",
            wrong_length_digest,
            message_type="DIGEST",
            hash_algorithm="SHA256",
        )


@pytest.mark.parametrize("algorithm", ["SHA256", "SHA512"])
def test_digest_mode_accepts_correctly_sized_digest_for_each_supported_algorithm(
    transit: TransitService, algorithm: str
):
    transit.create_key(ALICE, "doc-signer", key_type="asymmetric_sign")
    digest = b"\x42" * DIGEST_LENGTH_BYTES[algorithm]

    signature = transit.sign(
        ALICE, "doc-signer", digest, message_type="DIGEST", hash_algorithm=algorithm
    )
    result = transit.verify(
        ALICE, "doc-signer", digest, signature, message_type="DIGEST", hash_algorithm=algorithm
    )
    assert result.signature_valid is True


def test_message_type_validation_happens_before_any_key_lookup(transit: TransitService):
    with pytest.raises(InvalidMessageType):
        transit.sign(
            ALICE, "this-key-does-not-exist", b"x", message_type="RAW", hash_algorithm="SHA256"
        )


def test_signing_operation_rejected_on_a_symmetric_key(transit: TransitService):
    transit.create_key(ALICE, "sym-key", key_type="symmetric")
    with pytest.raises(WrongKeyType):
        transit.sign(ALICE, "sym-key", b"message")


def test_encrypt_rejected_on_a_signing_key(transit: TransitService):
    transit.create_key(ALICE, "sig-key", key_type="asymmetric_sign")
    with pytest.raises(WrongKeyType):
        transit.encrypt(ALICE, "sig-key", b"data")
