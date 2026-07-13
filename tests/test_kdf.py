from aegis.crypto.kdf import KdfParams, derive_master_key
from aegis.crypto.random import generate_salt

# Deliberately weak params for running test suite quickly.
# Never use these in production.
_FAST_PARAMS = KdfParams(time_cost=1, memory_cost_kib=8, parallelism=1)


def test_same_passphrase_and_salt_are_deterministic() -> None:
    salt = generate_salt()
    key_a = derive_master_key("correct horse battery staple", salt, _FAST_PARAMS)
    key_b = derive_master_key("correct horse battery staple", salt, _FAST_PARAMS)
    assert key_a == key_b


def test_different_salts_produce_different_keys() -> None:
    salt_a = generate_salt()
    salt_b = generate_salt()
    key_a = derive_master_key("same passphrase", salt_a, _FAST_PARAMS)
    key_b = derive_master_key("same passphrase", salt_b, _FAST_PARAMS)
    assert key_a != key_b


def test_different_passphrases_produce_different_keys() -> None:
    salt = generate_salt()
    key_a = derive_master_key("passphrase one", salt, _FAST_PARAMS)
    key_b = derive_master_key("passphrase two", salt, _FAST_PARAMS)
    assert key_a != key_b


def test_key_length_is_32_bytes() -> None:
    salt = generate_salt()
    key = derive_master_key("whatever", salt, _FAST_PARAMS)
    assert len(key) == 32


def test_empty_passphrase_rejected() -> None:
    import pytest

    salt = generate_salt()
    with pytest.raises(ValueError):
        derive_master_key("", salt, _FAST_PARAMS)
