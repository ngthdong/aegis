from __future__ import annotations

from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw

MASTER_KEY_LENGTH_BYTES = 32  # AES-256 key size


@dataclass(frozen=True, slots=True)
class KdfParams:
    """
    Argon2id cost parameters, persisted alongside the salt at init time.
    Never hardcode these at the call site in vault_core,
    it always read them back from what was persisted.
    """

    time_cost: int = 3
    memory_cost_kib: int = 65536
    parallelism: int = 4

    def __post_init__(self) -> None:
        if self.time_cost < 1:
            raise ValueError("time_cost must be >= 1")
        if self.memory_cost_kib < 8 * self.parallelism:
            raise ValueError("memory_cost_kib too low for given parallelism")
        if self.parallelism < 1:
            raise ValueError("parallelism must be >= 1")


def derive_master_key(passphrase: str, salt: bytes, params: KdfParams) -> bytes:
    """
    Derive a 32-byte Master Key from a passphrase + salt using Argon2id.
    """
    if not passphrase:
        raise ValueError("passphrase must not be empty")

    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost_kib,
        parallelism=params.parallelism,
        hash_len=MASTER_KEY_LENGTH_BYTES,
        type=Type.ID,
    )
