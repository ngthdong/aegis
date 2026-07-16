import pytest

from aegis.core.repository import InMemoryVaultRepository
from aegis.core.service import (
    InvalidPassphrase,
    VaultAlreadyInitialized,
    VaultNotInitialized,
    VaultService,
)
from aegis.core.state import VaultState
from aegis.crypto.kdf import KdfParams

_FAST_PARAMS = KdfParams(time_cost=1, memory_cost_kib=8, parallelism=1)


@pytest.fixture
def vault() -> VaultService:
    return VaultService(InMemoryVaultRepository(), kdf_params=_FAST_PARAMS)


def test_starts_uninitialized(vault: VaultService) -> None:
    assert vault.status() == VaultState.UNINITIALIZED


def test_initialize_leaves_vault_sealed_not_unsealed(vault: VaultService) -> None:
    vault.initialize("correct horse battery staple.")
    assert vault.status() == VaultState.SEALED


def test_cannot_initialize_twice(vault: VaultService) -> None:
    vault.initialize("first passphrase")
    with pytest.raises(VaultAlreadyInitialized):
        vault.initialize("second passphrase")


def test_unseal_with_correct_passphrase_succeeds(vault: VaultService) -> None:
    vault.initialize("correct horse battery staple")
    vault.unseal("correct horse battery staple")
    assert vault.status() == VaultState.UNSEALED


def test_unseal_with_wrong_passphrase_fails(vault: VaultService) -> None:
    vault.initialize("correct horse battery staple")
    with pytest.raises(InvalidPassphrase):
        vault.unseal("wrong passphrase entirely")
    # A failed unseal must not leave the vault half-unsealed.
    assert vault.status() == VaultState.SEALED


def test_cannot_unseal_before_initialize(vault: VaultService) -> None:
    with pytest.raises(VaultNotInitialized):
        vault.unseal("anything")


def test_seal_discards_in_memory_dek(vault: VaultService) -> None:
    vault.initialize("correct horse battery staple")
    vault.unseal("correct horse battery staple")
    assert vault.status() == VaultState.UNSEALED

    vault.seal()
    assert vault.status() == VaultState.SEALED

    with pytest.raises(VaultNotInitialized):
        vault.get_dek()


def test_get_dek_requires_unsealed_state(vault: VaultService) -> None:
    with pytest.raises(VaultNotInitialized):
        vault.get_dek()  # never initialized

    vault.initialize("correct horse battery staple")
    with pytest.raises(VaultNotInitialized):
        vault.get_dek()  # initialized but sealed


def test_dek_is_stable_across_seal_unseal_cycles(vault: VaultService) -> None:
    """
    The DEK derived on first unseal must be the SAME DEK on every
    subsequent unseal. It's generated once at initialize() and then
    only ever unwrapped, never regenerated. This is the property that
    makes it possible to seal/unseal a running vault without corrupting
    already-encrypted data.
    """
    vault.initialize("correct horse battery staple")

    vault.unseal("correct horse battery staple")
    dek_first = vault.get_dek()
    vault.seal()

    vault.unseal("correct horse battery staple")
    dek_second = vault.get_dek()

    assert dek_first == dek_second


def test_corrupted_persisted_data_is_reported_as_invalid_passphrase(vault: VaultService) -> None:
    """
    Tamper test: if the persisted DEK envelope is corrupted (bit flip,
    disk corruption, malicious modification), unseal must fail cleanly.
    Never silently return garbage key material, never crash with an
    unhandled exception.
    """
    vault.initialize("correct horse battery staple")

    # Reach into the repository directly to simulate on-disk corruption.
    # This is the one place in this test file that's allowed to know about
    # VaultMeta's internals, precisely because it's proving what happens
    # when that data is corrupted outside the service's control.
    from dataclasses import replace

    repo = vault._repository  # type: ignore[attr-defined]
    meta = repo.load()
    tampered_ciphertext = bytearray(meta.dek_envelope.ciphertext)
    tampered_ciphertext[0] ^= 0xFF
    tampered_envelope = replace(meta.dek_envelope, ciphertext=bytes(tampered_ciphertext))
    repo.save(replace(meta, dek_envelope=tampered_envelope))

    with pytest.raises(InvalidPassphrase):
        vault.unseal("correct horse battery staple")
