from __future__ import annotations

import pytest

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
def unsealed_vault() -> VaultService:
    vault = VaultService(InMemoryVaultRepository())
    vault.initialize("correct horse battery staple")
    vault.unseal("correct horse battery staple")
    return vault


@pytest.fixture
def kv(unsealed_vault: VaultService) -> KvService:
    return KvService(InMemorySecretRepository(), AuthzService(), unsealed_vault, FakeClock())


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
    kv = KvService(InMemorySecretRepository(), AuthzService(), unsealed_vault, FakeClock())
    with pytest.raises(VaultNotInitialized):
        kv.write(ALICE, "secret/path", {"value": "x"})
