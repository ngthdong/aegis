from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass
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
from aegis.transit.models import (
    DIGEST_LENGTH_BYTES,
    VERSION_TAG_LENGTH_BYTES,
    HashAlgorithm,
    MessageType,
    TransitKey,
    TransitKeyType,
    TransitKeyVersion,
    pack_version_tag,
    unpack_version_tag,
)
from aegis.transit.repository import TransitKeyRepository

_RESOURCE_TYPE = "transit_key"
_ED25519_SIGNATURE_LENGTH_BYTES = 64


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


class TransitKeyVersionNotFound(Exception):
    pass


class InvalidMessageType(Exception):
    pass


@dataclass(frozen=True, slots=True)
class VerifyResult:
    key_name: str
    signature_valid: bool
    signing_algorithm: str


def _wrap_aad(owner_id: str, name: str, version: int) -> bytes:
    return f"transit-key:{owner_id}:{name}:{version}".encode()


def _validate_message_type_and_digest(
    message: bytes, message_type: MessageType, hash_algorithm: HashAlgorithm | None
) -> None:
    if message_type == "RAW":
        if hash_algorithm is not None:
            raise InvalidMessageType("hash_algorithm must not be supplied when message_type is RAW")
        return
    if hash_algorithm is None:
        raise InvalidMessageType("hash_algorithm is required when message_type is DIGEST")
    expected_length = DIGEST_LENGTH_BYTES[hash_algorithm]
    if len(message) != expected_length:
        raise InvalidMessageType(
            f"message length {len(message)} does not match expected "
            f"{hash_algorithm} digest length of {expected_length} bytes"
        )


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

        key_id = uuid.uuid4().hex
        now = self._clock.now()
        wrapped, public_key, algorithm = self._generate_version_material(
            principal.user_id, name, key_type, version=1
        )

        key = TransitKey(
            id=key_id,
            name=name,
            owner_id=principal.user_id,
            key_type=key_type,
            algorithm=algorithm,
            current_version=1,
            disabled=False,
            destroyed_at=None,
            created_at=now,
        )
        first_version = TransitKeyVersion(
            id=uuid.uuid4().hex,
            transit_key_id=key_id,
            version=1,
            wrapped_key=wrapped,
            public_key=public_key,
            created_at=now,
        )
        self._repository.create_key(key, first_version)
        self._record(principal, action, name, "success", {"key_type": key_type})

    def rotate_key(self, principal: Principal, name: str) -> int:
        key = self._get_owned_key(principal, "rotate", name)
        if key.is_destroyed:
            self._record(principal, "transit.rotate", name, "error", {"reason": "destroyed"})
            raise TransitKeyDestroyed(f"transit key '{name}' has been destroyed")

        new_version_number = key.current_version + 1
        wrapped, public_key, _algorithm = self._generate_version_material(
            key.owner_id, name, key.key_type, version=new_version_number
        )
        self._repository.add_version(
            TransitKeyVersion(
                id=uuid.uuid4().hex,
                transit_key_id=key.id,
                version=new_version_number,
                wrapped_key=wrapped,
                public_key=public_key,
                created_at=self._clock.now(),
            )
        )
        self._repository.bump_current_version(key.id, new_version_number)
        self._record(
            principal, "transit.rotate", name, "success", {"new_version": new_version_number}
        )
        return new_version_number

    def _generate_version_material(
        self, owner_id: str, name: str, key_type: TransitKeyType, version: int
    ) -> tuple[Envelope, bytes | None, str]:
        dek = self._vault.get_dek()
        aad = _wrap_aad(owner_id, name, version)
        if key_type == "symmetric":
            raw_key = generate_aes_key()
            return encrypt(dek, raw_key, aad=aad), None, "AES-256-GCM"
        keypair = generate_keypair()
        wrapped = encrypt(dek, keypair.private_key_bytes, aad=aad)
        return wrapped, keypair.public_key_bytes, "Ed25519"

    def encrypt(self, principal: Principal, name: str, plaintext: bytes) -> str:
        key, current = self._load_current_version_for_use(
            principal, "encrypt", name, expected_type="symmetric"
        )
        raw_key = self._unwrap(key, current, key.current_version)
        envelope = encrypt(raw_key, plaintext)
        blob = pack_version_tag(key.current_version) + envelope.nonce + envelope.ciphertext
        self._record(
            principal, "transit.encrypt", name, "success", {"version": key.current_version}
        )
        return base64.b64encode(blob).decode("ascii")

    def decrypt(self, principal: Principal, name: str, ciphertext_b64: str) -> bytes:
        key = self._get_owned_key(principal, "decrypt", name)
        if key.is_destroyed:
            self._record(principal, "transit.decrypt", name, "error", {"reason": "destroyed"})
            raise TransitKeyDestroyed(f"transit key '{name}' has been destroyed")

        raw = base64.b64decode(ciphertext_b64)

        result = self._try_versioned_decrypt(key, raw)
        if result is not None:
            version, plaintext = result
            self._record(principal, "transit.decrypt", name, "success", {"version": version})
            return plaintext

        legacy = self._try_legacy_decrypt(key, raw)
        if legacy is not None:
            self._record(
                principal, "transit.decrypt", name, "success", {"version": 1, "format": "legacy"}
            )
            return legacy

        self._record(principal, "transit.decrypt", name, "error", {"reason": "invalid_ciphertext"})
        raise TransitDecryptionFailed(f"ciphertext could not be decrypted under key '{name}'")

    def _try_versioned_decrypt(self, key: TransitKey, raw: bytes) -> tuple[int, bytes] | None:
        parsed = unpack_version_tag(raw)
        if parsed is None:
            return None
        version, remainder = parsed
        version_row = self._repository.get_version(key.id, version)
        if version_row is None or version_row.wrapped_key is None:
            return None
        if len(remainder) < NONCE_LENGTH_BYTES:
            return None
        try:
            raw_key = self._unwrap(key, version_row, version)
            nonce, ciphertext = remainder[:NONCE_LENGTH_BYTES], remainder[NONCE_LENGTH_BYTES:]
            plaintext = aead_decrypt(raw_key, Envelope(nonce=nonce, ciphertext=ciphertext))
        except DecryptionError:
            return None
        return version, plaintext

    def _try_legacy_decrypt(self, key: TransitKey, raw: bytes) -> bytes | None:
        version_row = self._repository.get_version(key.id, 1)
        if version_row is None or version_row.wrapped_key is None:
            return None
        if len(raw) < NONCE_LENGTH_BYTES:
            return None
        try:
            raw_key = self._unwrap(key, version_row, 1)
            nonce, ciphertext = raw[:NONCE_LENGTH_BYTES], raw[NONCE_LENGTH_BYTES:]
            return aead_decrypt(raw_key, Envelope(nonce=nonce, ciphertext=ciphertext))
        except DecryptionError:
            return None

    def sign(
        self,
        principal: Principal,
        name: str,
        message: bytes,
        message_type: MessageType = "RAW",
        hash_algorithm: HashAlgorithm | None = None,
    ) -> str:
        _validate_message_type_and_digest(message, message_type, hash_algorithm)
        key, current = self._load_current_version_for_use(
            principal, "sign", name, expected_type="asymmetric_sign"
        )
        private_key_bytes = self._unwrap(key, current, key.current_version)
        signature = ed25519_sign(private_key_bytes, message)
        blob = pack_version_tag(key.current_version) + signature
        self._record(principal, "transit.sign", name, "success", {"version": key.current_version})
        return base64.b64encode(blob).decode("ascii")

    def verify(
        self,
        principal: Principal,
        name: str,
        message: bytes,
        signature_b64: str,
        message_type: MessageType = "RAW",
        hash_algorithm: HashAlgorithm | None = None,
    ) -> VerifyResult:
        _validate_message_type_and_digest(message, message_type, hash_algorithm)

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

        raw_signature = base64.b64decode(signature_b64)

        if len(raw_signature) == VERSION_TAG_LENGTH_BYTES + _ED25519_SIGNATURE_LENGTH_BYTES:
            parsed = unpack_version_tag(raw_signature)
            assert parsed is not None
            version, signature = parsed
        elif len(raw_signature) == _ED25519_SIGNATURE_LENGTH_BYTES:
            version, signature = 1, raw_signature  # legacy, pre-rotation format
        else:
            self._record(
                principal, "transit.verify", name, "error", {"reason": "invalid_signature_format"}
            )
            raise TransitDecryptionFailed(f"malformed signature for key '{name}'")

        version_row = self._repository.get_version(key.id, version)
        if version_row is None or version_row.public_key is None:
            self._record(
                principal,
                "transit.verify",
                name,
                "error",
                {"reason": "version_not_found", "version": version},
            )
            raise TransitKeyVersionNotFound(f"key '{name}' has no version {version}")

        is_valid = ed25519_verify(version_row.public_key, message, signature)
        self._record(
            principal,
            "transit.verify",
            name,
            "success",
            {"signature_valid": is_valid, "version": version},
        )
        return VerifyResult(
            key_name=name, signature_valid=is_valid, signing_algorithm=key.algorithm
        )

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

    def _load_current_version_for_use(
        self, principal: Principal, action: str, name: str, expected_type: TransitKeyType
    ) -> tuple[TransitKey, TransitKeyVersion]:
        key = self._get_owned_key(principal, action, name)
        if key.key_type != expected_type:
            self._record(
                principal, f"transit.{action}", name, "error", {"reason": "wrong_key_type"}
            )
            raise WrongKeyType(f"key '{name}' is not a {expected_type} key")
        if key.is_destroyed:
            self._record(principal, f"transit.{action}", name, "error", {"reason": "destroyed"})
            raise TransitKeyDestroyed(f"transit key '{name}' has been destroyed")
        if key.disabled:
            self._record(principal, f"transit.{action}", name, "error", {"reason": "disabled"})
            raise TransitKeyDisabled(f"transit key '{name}' is disabled")

        current = self._repository.get_version(key.id, key.current_version)
        assert current is not None  # invariant: a non-destroyed key always has a current version
        return key, current

    def _unwrap(self, key: TransitKey, version_row: TransitKeyVersion, version: int) -> bytes:
        dek = self._vault.get_dek()
        assert version_row.wrapped_key is not None
        return aead_decrypt(
            dek, version_row.wrapped_key, aad=_wrap_aad(key.owner_id, key.name, version)
        )
