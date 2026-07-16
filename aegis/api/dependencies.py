from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request

from aegis.auth.repository import SqlUserRepository
from aegis.auth.service import AuthService
from aegis.common.errors import VaultSealedError
from aegis.core.service import VaultService
from aegis.core.state import VaultState


def get_vault_service(request: Request) -> VaultService:
    return request.app.state.vault_service


def get_auth_service(request: Request) -> AuthService:
    repository = SqlUserRepository(request.app.state.session_factory)
    return AuthService(repository)


def require_vault_unsealed(
    vault: Annotated[VaultService, Depends(get_vault_service)],
) -> None:
    if vault.status() != VaultState.UNSEALED:
        raise VaultSealedError("vault must be unsealed to perform this operation")


VaultServiceDependency = Annotated[VaultService, Depends(get_vault_service)]
AuthServiceDependency = Annotated[AuthService, Depends(get_auth_service)]
RequireVaultUnsealed = Annotated[None, Depends(require_vault_unsealed)]
