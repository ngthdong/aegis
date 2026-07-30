from __future__ import annotations

import json
import uuid
from typing import Any, cast

from aegis.audit.logger import AuditLogger
from aegis.auth.session_service import Principal
from aegis.authz.service import AuthzService, PermissionDenied
from aegis.common.clock import Clock
from aegis.core.service import VaultService
from aegis.crypto.aead import DecryptionError, encrypt
from aegis.crypto.aead import decrypt as aead_decrypt
from aegis.kv.models import Secret, SecretVersion
from aegis.kv.repository import SecretRepository

_RESOURCE_TYPE = "secret"


class SecretNotFound(Exception):
    pass


class SecretVersionNotFound(Exception):
    pass


class SecretCorrupted(Exception):
    pass


def _aad(owner_id: str, path: str, version: int) -> bytes:
    return f"{owner_id}:{path}:{version}".encode()


class KvService:
    def __init__(
        self,
        repository: SecretRepository,
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
        path: str,
        outcome: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._audit.record(
            principal_id=principal.user_id,
            action=action,
            resource_type=_RESOURCE_TYPE,
            resource_id=path,
            outcome=outcome,  # type: ignore[arg-type]
            metadata=metadata,
        )

    def write(self, principal: Principal, path: str, value: dict[str, Any]) -> int:
        existing = self._repository.get_by_path(path)
        now = self._clock.now()

        if existing is not None:
            try:
                self._authz.require(principal, "write", existing)
            except PermissionDenied:
                self._record(principal, "kv.write", path, "denied")
                raise
            owner_id = existing.owner_id
            new_version_number = existing.current_version + 1
            secret_id = existing.id
        else:
            owner_id = principal.user_id
            new_version_number = 1
            secret_id = uuid.uuid4().hex

        dek = self._vault.get_dek()
        plaintext = json.dumps(value).encode("utf-8")
        envelope = encrypt(dek, plaintext, aad=_aad(owner_id, path, new_version_number))

        if existing is None:
            self._repository.create_secret(
                Secret(
                    id=secret_id,
                    path=path,
                    owner_id=owner_id,
                    current_version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
        self._repository.add_version(
            SecretVersion(
                id=uuid.uuid4().hex,
                secret_id=secret_id,
                version=new_version_number,
                envelope=envelope,
                created_at=now,
            )
        )
        if existing is not None:
            self._repository.bump_current_version(secret_id, new_version_number, now)

        self._record(principal, "kv.write", path, "success", {"version": new_version_number})
        return new_version_number

    def read(self, principal: Principal, path: str, version: int | None = None) -> dict[str, Any]:
        secret = self._repository.get_by_path(path)
        if secret is None:
            self._record(principal, "kv.read", path, "error", {"reason": "not_found"})
            raise SecretNotFound(f"no secret at path '{path}'")

        try:
            self._authz.require(principal, "read", secret)
        except PermissionDenied:
            self._record(principal, "kv.read", path, "denied")
            raise

        target_version = version if version is not None else secret.current_version
        version_row = self._repository.get_version(secret.id, target_version)
        if version_row is None:
            self._record(
                principal,
                "kv.read",
                path,
                "error",
                {"reason": "version_not_found", "version": target_version},
            )
            raise SecretVersionNotFound(f"path '{path}' has no version {target_version}")

        dek = self._vault.get_dek()
        try:
            plaintext = aead_decrypt(
                dek, version_row.envelope, aad=_aad(secret.owner_id, path, target_version)
            )
        except DecryptionError as exc:
            self._record(
                principal,
                "kv.read",
                path,
                "error",
                {"reason": "corrupted", "version": target_version},
            )
            raise SecretCorrupted(
                f"secret at path '{path}' version {target_version} failed integrity verification"
            ) from exc

        self._record(principal, "kv.read", path, "success", {"version": target_version})

        return cast(dict[str, Any], json.loads(plaintext))

    def delete(self, principal: Principal, path: str) -> None:
        secret = self._repository.get_by_path(path)
        if secret is None:
            self._record(principal, "kv.delete", path, "error", {"reason": "not_found"})
            raise SecretNotFound(f"no secret at path '{path}'")

        try:
            self._authz.require(principal, "delete", secret)
        except PermissionDenied:
            self._record(principal, "kv.delete", path, "denied")
            raise

        self._repository.delete(path)
        self._record(
            principal, "kv.delete", path, "success", {"versions_deleted": secret.current_version}
        )
