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
from aegis.crypto.signing import generate_keypair
from aegis.crypto.signing import sign as ed25519_sign
from aegis.crypto.signing import verify as ed25519_verify
from aegis.transit.models import TransitKey, TransitKeyType
from aegis.transit.repository import TransitKeyRepository

_RESOURCE_TYPE = "transit_key"


class TransitKeyNotFound(Exception):
    pass


class TransitKeyAlreadyExists(Exception):
    pass


class TransitKeyDisabled(Exception):
    pass


class TransitKeyDestroyed(Exception):
    pass


class WrongKeyType(Exception):
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

    def create_key(
        self, principal: Principal, name: str, key_type: TransitKeyType = "symmetric"
    ) -> None:
        action = "transit.create_key"
        if self._repository.get_by_name(name) is not None:
            self._record(principal, action, name, "error", {"reason": "exists"})
            raise TransitKeyAlreadyExists(f"transit key '{name}' already exists")

        dek = self._vault.get_dek()
        aad = _wrap_aad(principal.user_id, name)

        if key_type == "symmetric":
            raw_key = generate_aes_key()
            wrapped = encrypt(dek, raw_key, aad=aad)
            public_key = None
        else:  # "asymmetric_sign"
            keypair = generate_keypair()
            wrapped = encrypt(dek, keypair.private_key_bytes, aad=aad)
            public_key = keypair.public_key_bytes

        self._repository.save(
            TransitKey(
                id=uuid.uuid4().hex,
                name=name,
                owner_id=principal.user_id,
                key_type=key_type,
                algorithm="AES-256-GCM" if key_type == "symmetric" else "Ed25519",
                wrapped_key=wrapped,
                public_key=public_key,
                disabled=False,
                destroyed_at=None,
                created_at=self._clock.now(),
            )
        )
        self._record(principal, action, name, "success", {"key_type": key_type})

    def encrypt(self, principal: Principal, name: str, plaintext: bytes) -> str:
        raw_key = self._load_wrapped_secret_for_use(
            principal, "encrypt", name, expected_type="symmetric", require_ownership=True
        )
        envelope = encrypt(raw_key, plaintext)
        blob = base64.b64encode(envelope.nonce + envelope.ciphertext).decode("ascii")
        self._record(principal, "transit.encrypt", name, "success")
        return blob

    def decrypt(self, principal: Principal, name: str, ciphertext_b64: str) -> bytes:
        raw_key = self._load_wrapped_secret_for_use(
            principal,
            "decrypt",
            name,
            expected_type="symmetric",
            require_ownership=True,
            allow_disabled=True,
        )

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

    def sign(self, principal: Principal, name: str, message: bytes) -> str:
        private_key_bytes = self._load_wrapped_secret_for_use(
            principal, "sign", name, expected_type="asymmetric_sign", require_ownership=True
        )
        signature = ed25519_sign(private_key_bytes, message)
        self._record(principal, "transit.sign", name, "success")
        return base64.b64encode(signature).decode("ascii")

    def verify(self, principal: Principal, name: str, message: bytes, signature_b64: str) -> bool:
        key = self._repository.get_by_name(name)
        if key is None:
            self._record(principal, "transit.verify", name, "error", {"reason": "not_found"})
            raise TransitKeyNotFound(f"no transit key named '{name}'")

        if key.key_type != "asymmetric_sign":
            self._record(principal, "transit.verify", name, "error", {"reason": "wrong_key_type"})
            raise WrongKeyType(f"key '{name}' is not a signing key")

        if key.is_destroyed:
            self._record(principal, "transit.verify", name, "error", {"reason": "destroyed"})
            raise TransitKeyDestroyed(f"transit key '{name}' has been destroyed")

        assert key.public_key is not None  # invariant: non-destroyed signing key always has one

        is_valid = ed25519_verify(key.public_key, message, base64.b64decode(signature_b64))
        self._record(principal, "transit.verify", name, "success", {"signature_valid": is_valid})
        return is_valid

    def disable_key(self, principal: Principal, name: str) -> None:
        key = self._get_owned_key(principal, "disable", name)
        if key.is_destroyed:
            self._record(principal, "transit.disable", name, "error", {"reason": "destroyed"})
            raise TransitKeyDestroyed(f"transit key '{name}' has been destroyed")

        self._repository.set_disabled(name, True)
        self._record(principal, "transit.disable", name, "success")

    def destroy_key(self, principal: Principal, name: str) -> None:
        key = self._get_owned_key(principal, "destroy", name)
        if key.is_destroyed:
            self._record(
                principal, "transit.destroy", name, "error", {"reason": "already_destroyed"}
            )
            raise TransitKeyDestroyed(f"transit key '{name}' has already been destroyed")

        self._repository.destroy(name, self._clock.now())
        self._record(principal, "transit.destroy", name, "success")

    def _get_owned_key(self, principal: Principal, action: str, name: str) -> TransitKey:
        key = self._repository.get_by_name(name)
        if key is None:
            self._record(principal, f"transit.{action}", name, "error", {"reason": "not_found"})
            raise TransitKeyNotFound(f"no transit key named '{name}'")

        try:
            self._authz.require(principal, action, key)
        except PermissionDenied:
            self._record(principal, f"transit.{action}", name, "denied")
            raise

        return key

    def _load_wrapped_secret_for_use(
        self,
        principal: Principal,
        action: str,
        name: str,
        expected_type: TransitKeyType,
        require_ownership: bool,
        allow_disabled: bool = False,
    ) -> bytes:
        key = self._repository.get_by_name(name)
        if key is None:
            self._record(principal, f"transit.{action}", name, "error", {"reason": "not_found"})
            raise TransitKeyNotFound(f"no transit key named '{name}'")

        if require_ownership:
            try:
                self._authz.require(principal, action, key)
            except PermissionDenied:
                self._record(principal, f"transit.{action}", name, "denied")
                raise

        if key.key_type != expected_type:
            self._record(
                principal, f"transit.{action}", name, "error", {"reason": "wrong_key_type"}
            )
            raise WrongKeyType(f"key '{name}' is not a {expected_type} key")

        if key.is_destroyed:
            self._record(principal, f"transit.{action}", name, "error", {"reason": "destroyed"})
            raise TransitKeyDestroyed(f"transit key '{name}' has been destroyed")

        if key.disabled and not allow_disabled:
            self._record(principal, f"transit.{action}", name, "error", {"reason": "disabled"})
            raise TransitKeyDisabled(f"transit key '{name}' is disabled")

        assert key.wrapped_key is not None  # invariant: non-destroyed key always has one
        dek = self._vault.get_dek()
        return aead_decrypt(dek, key.wrapped_key, aad=_wrap_aad(key.owner_id, name))
