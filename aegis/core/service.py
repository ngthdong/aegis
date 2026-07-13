"""
VaultService is the root of trust for the whole system.

Owns the seal/unseal state machine and Master Key derivation. Nothing
outside this module should ever construct a Master Key or hold a DEK
directly

KV and Transit go through `VaultService.get_dek()` instead of
deriving/decrypting anything themselves.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from aegis.core.state import VaultState
from aegis.crypto.aead import DecryptionError, Envelope, decrypt, encrypt
from aegis.crypto.kdf import KdfParams, derive_master_key
from aegis.crypto.random import generate_dek, generate_salt

_DEK_AAD = b"vault-dek"


@dataclass(frozen=True, slots=True)
class VaultMeta:
    kdf_salt: bytes
    kdf_params: KdfParams
    dek_envelope: Envelope
    initialized_at: datetime


class VaultRepository(Protocol):
    """
    Abstract interface for persisting vault metadata.
    """

    def load(self) -> VaultMeta | None: ...
    def save(self, meta: VaultMeta) -> None: ...


class VaultAlreadyInitialized(Exception):
    pass


class VaultNotInitialized(Exception):
    pass


class InvalidPassphrase(Exception):
    """
    Raised when unseal fails: wrong passphrase or corrupted persisted
    data are deliberately reported identically.
    """


class VaultService:
    def __init__(
        self,
        repository: VaultRepository,
        kdf_params: KdfParams | None = None,
    ) -> None:
        self._repository = repository
        self._default_kdf_params = kdf_params or KdfParams()
        self._dek: bytes | None = None  # in-memory only

    def status(self) -> VaultState:
        if self._dek is not None:
            return VaultState.UNSEALED
        if self._repository.load() is not None:
            return VaultState.SEALED
        return VaultState.UNINITIALIZED

    def initialize(self, passphrase: str) -> None:
        if self._repository.load() is not None:
            raise VaultAlreadyInitialized("vault is already initialized")

        salt = generate_salt()
        params = self._default_kdf_params
        master_key = derive_master_key(passphrase, salt, params)

        try:
            dek = generate_dek()
            dek_envelope = encrypt(master_key, dek, aad=_DEK_AAD)
        finally:
            master_key = b"\x00" * len(master_key)

        meta = VaultMeta(
            kdf_salt=salt,
            kdf_params=params,
            dek_envelope=dek_envelope,
            initialized_at=datetime.now(UTC),
        )
        self._repository.save(meta)

    def unseal(self, passphrase: str) -> None:
        meta = self._repository.load()
        if meta is None:
            raise VaultNotInitialized("vault has not been initialized")

        master_key = derive_master_key(passphrase, meta.kdf_salt, meta.kdf_params)
        try:
            dek = decrypt(master_key, meta.dek_envelope, aad=_DEK_AAD)
        except DecryptionError as exc:
            raise InvalidPassphrase("incorrect passphrase or corrupted vault data") from exc
        finally:
            master_key = b"\x00" * len(master_key)

        self._dek = dek

    def seal(self) -> None:
        self._dek = None

    def get_dek(self) -> bytes:
        if self._dek is None:
            raise VaultNotInitialized("vault is sealed or not initialized")
        return self._dek
