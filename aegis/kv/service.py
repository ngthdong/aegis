from __future__ import annotations

import json
import uuid
from typing import Any, cast

from aegis.auth.session_service import Principal
from aegis.authz.service import AuthzService
from aegis.common.clock import Clock
from aegis.core.service import VaultService
from aegis.crypto.aead import DecryptionError, encrypt
from aegis.crypto.aead import decrypt as aead_decrypt
from aegis.kv.models import Secret
from aegis.kv.repository import SecretRepository


class SecretNotFound(Exception):
    pass


class SecretCorrupted(Exception):
    pass


def _aad(owner_id: str, path: str) -> bytes:
    return f"{owner_id}:{path}".encode()


class KvService:
    def __init__(
        self,
        repository: SecretRepository,
        authz: AuthzService,
        vault: VaultService,
        clock: Clock,
    ) -> None:
        self._repository = repository
        self._authz = authz
        self._vault = vault
        self._clock = clock

    def write(self, principal: Principal, path: str, value: dict[str, Any]) -> None:
        existing = self._repository.get_by_path(path)
        now = self._clock.now()

        if existing is not None:
            self._authz.require(principal, "write", existing)
            owner_id = existing.owner_id  # overwrite never changes ownership
            created_at = existing.created_at
        else:
            owner_id = principal.user_id
            created_at = now

        dek = self._vault.get_dek()
        plaintext = json.dumps(value).encode("utf-8")
        envelope = encrypt(dek, plaintext, aad=_aad(owner_id, path))

        self._repository.save(
            Secret(
                id=existing.id if existing is not None else uuid.uuid4().hex,
                path=path,
                owner_id=owner_id,
                envelope=envelope,
                created_at=created_at,
                updated_at=now,
            )
        )

    def read(self, principal: Principal, path: str) -> dict[str, Any]:
        secret = self._repository.get_by_path(path)
        if secret is None:
            raise SecretNotFound(f"no secret at path '{path}'")

        self._authz.require(principal, "read", secret)

        dek = self._vault.get_dek()
        try:
            plaintext = aead_decrypt(dek, secret.envelope, aad=_aad(secret.owner_id, path))
        except DecryptionError as exc:
            raise SecretCorrupted(f"secret at path '{path}' failed integrity verification") from exc

        return cast(dict[str, Any], json.loads(plaintext))

    def delete(self, principal: Principal, path: str) -> None:
        secret = self._repository.get_by_path(path)
        if secret is None:
            raise SecretNotFound(f"no secret at path '{path}'")

        self._authz.require(principal, "delete", secret)
        self._repository.delete(path)
