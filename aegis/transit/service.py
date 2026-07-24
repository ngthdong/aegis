from __future__ import annotations

import base64
import uuid
from typing import Any

from aegis.audit.logger import AuditLogger
from aegis.auth.session_service import Principal
from aegis.authz.service import AuthzService, PermissionDenied
from aegis.common.clock import Clock
from aegis.core.service import VaultService
from aegis.crypto.aead import NONCE_LENGTH_BYTES, DecryptionError, Envelope, encrypt
from aegis.crypto.aead import decrypt as aead_decrypt
from aegis.crypto.random import generate_dek as generate_aes_key
from aegis.transit.models import TransitKey
from aegis.transit.repository import TransitKeyRepository

_RESOURCE_TYPE = "transit_key"
_ALGORITHM = "AES-256-GCM"


class TransitKeyNotFound(Exception):
    pass


class TransitKeyAlreadyExists(Exception):
    pass


class TransitKeyDisabled(Exception):
    pass


class TransitDecryptionFailed(Exception):
    pass


def _wrap_aad(owner_id: str, name: str) -> bytes:
    return f"transit-key:{owner_id}:{name}".encode()


class TransitService:
    def __init__(
        self,
        repository: TransitKeyRepository,
        authz: AuthzService,
        vault: VaultService,
        clock: Clock,
        audit: AuditLogger,
    ) -> None:
        self._repository = repository
        self._authz = authz
        self._vault = vault
        self._clock = clock
        self._audit = audit

    def _record(
        self,
        principal: Principal,
        action: str,
        name: str,
        outcome: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._audit.record(
            principal_id=principal.user_id,
            action=action,
            resource_type=_RESOURCE_TYPE,
            resource_id=name,
            outcome=outcome,  # type: ignore[arg-type]
            metadata=metadata,
        )

    def create_key(self, principal: Principal, name: str) -> None:
        if self._repository.get_by_name(name) is not None:
            self._record(principal, "transit.create_key", name, "error", {"reason": "exists"})
            raise TransitKeyAlreadyExists(f"transit key '{name}' already exists")

        dek = self._vault.get_dek()
        raw_key = generate_aes_key()
        wrapped = encrypt(dek, raw_key, aad=_wrap_aad(principal.user_id, name))

        self._repository.save(
            TransitKey(
                id=uuid.uuid4().hex,
                name=name,
                owner_id=principal.user_id,
                algorithm=_ALGORITHM,
                wrapped_key=wrapped,
                disabled=False,
                created_at=self._clock.now(),
            )
        )
        self._record(principal, "transit.create_key", name, "success")

    def encrypt(self, principal: Principal, name: str, plaintext: bytes) -> str:
        raw_key = self._load_and_authorize_key(principal, "encrypt", name)
        envelope = encrypt(raw_key, plaintext)
        blob = base64.b64encode(envelope.nonce + envelope.ciphertext).decode("ascii")
        self._record(principal, "transit.encrypt", name, "success")
        return blob

    def decrypt(self, principal: Principal, name: str, ciphertext_b64: str) -> bytes:
        raw_key = self._load_and_authorize_key(principal, "decrypt", name)

        raw = base64.b64decode(ciphertext_b64)
        nonce, ciphertext = raw[:NONCE_LENGTH_BYTES], raw[NONCE_LENGTH_BYTES:]
        try:
            plaintext = aead_decrypt(raw_key, Envelope(nonce=nonce, ciphertext=ciphertext))
        except DecryptionError as exc:
            self._record(
                principal, "transit.decrypt", name, "error", {"reason": "invalid_ciphertext"}
            )
            raise TransitDecryptionFailed(
                f"ciphertext could not be decrypted under key '{name}'"
            ) from exc

        self._record(principal, "transit.decrypt", name, "success")
        return plaintext

    def _load_and_authorize_key(self, principal: Principal, action: str, name: str) -> bytes:
        key = self._repository.get_by_name(name)
        if key is None:
            self._record(principal, f"transit.{action}", name, "error", {"reason": "not_found"})
            raise TransitKeyNotFound(f"no transit key named '{name}'")

        try:
            self._authz.require(principal, action, key)
        except PermissionDenied:
            self._record(principal, f"transit.{action}", name, "denied")
            raise

        if key.disabled:
            self._record(principal, f"transit.{action}", name, "error", {"reason": "disabled"})
            raise TransitKeyDisabled(f"transit key '{name}' is disabled")

        dek = self._vault.get_dek()
        return aead_decrypt(dek, key.wrapped_key, aad=_wrap_aad(key.owner_id, name))
