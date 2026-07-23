from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from aegis.auth.repository import SqlUserRepository
from aegis.auth.service import AuthService
from aegis.auth.session_repository import SqlSessionRepository
from aegis.auth.session_service import (
    Principal,
    SessionExpired,
    SessionNotFound,
    SessionRevoked,
    SessionService,
)
from aegis.common.clock import Clock
from aegis.common.errors import InvalidSessionError, VaultSealedError
from aegis.core.service import VaultService
from aegis.core.state import VaultState

bearer_scheme = HTTPBearer(auto_error=False)


def get_vault_service(request: Request) -> VaultService:
    return request.app.state.vault_service


def get_clock(request: Request) -> Clock:
    return request.app.state.clock


def get_session_service(request: Request) -> SessionService:
    repository = SqlSessionRepository(request.app.state.session_factory)
    return SessionService(repository, request.app.state.clock)


def get_auth_service(request: Request) -> AuthService:
    user_repository = SqlUserRepository(request.app.state.session_factory)
    session_service = get_session_service(request)
    return AuthService(user_repository, session_service, request.app.state.clock)


def require_vault_unsealed(
    vault: Annotated[VaultService, Depends(get_vault_service)],
) -> None:
    if vault.status() != VaultState.UNSEALED:
        raise VaultSealedError("vault must be unsealed to perform this operation")


def get_current_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> Principal:
    if credentials is None:
        raise InvalidSessionError("missing bearer token")

    session_service = get_session_service(request)
    try:
        return session_service.validate(credentials.credentials)
    except (SessionNotFound, SessionExpired, SessionRevoked) as exc:
        raise InvalidSessionError("invalid or expired session") from exc


VaultServiceDependency = Annotated[VaultService, Depends(get_vault_service)]
AuthServiceDependency = Annotated[AuthService, Depends(get_auth_service)]
RequireVaultUnsealed = Annotated[None, Depends(require_vault_unsealed)]
CurrentPrincipal = Annotated[Principal, Depends(get_current_principal)]
SessionServiceDep = Annotated[SessionService, Depends(get_session_service)]
BearerCredentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)]
