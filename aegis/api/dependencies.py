from __future__ import annotations

from typing import Annotated, cast

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from aegis.audit.logger import AuditLogger
from aegis.audit.repository import SqlAuditRepository
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
from aegis.authz.service import AuthzService
from aegis.common.clock import Clock
from aegis.common.errors import InvalidSessionError, VaultSealedError
from aegis.core.service import VaultService
from aegis.core.state import VaultState
from aegis.kv.repository import SqlSecretRepository
from aegis.kv.service import KvService
from aegis.transit.repository import SqlTransitKeyRepository
from aegis.transit.service import TransitService

bearer_scheme = HTTPBearer(auto_error=False)


def get_vault_service(request: Request) -> VaultService:
    return cast(VaultService, request.app.state.vault_service)


def get_clock(request: Request) -> Clock:
    return cast(Clock, request.app.state.clock)


def get_session_service(request: Request) -> SessionService:
    repository = SqlSessionRepository(request.app.state.session_factory)
    return SessionService(repository, request.app.state.clock)


def get_auth_service(request: Request) -> AuthService:
    user_repository = SqlUserRepository(request.app.state.session_factory)
    session_service = get_session_service(request)
    return AuthService(
        user_repository, session_service, request.app.state.clock, request.app.state.metrics
    )


def get_authz_service() -> AuthzService:
    return AuthzService()


def get_audit_logger(request: Request) -> AuditLogger:
    repository = SqlAuditRepository(request.app.state.session_factory)
    return AuditLogger(repository, request.app.state.clock, request.app.state.metrics)


def get_audit_repository(request: Request) -> SqlAuditRepository:
    return SqlAuditRepository(request.app.state.session_factory)


def get_kv_service(request: Request) -> KvService:
    repository = SqlSecretRepository(request.app.state.session_factory)
    return KvService(
        repository,
        get_authz_service(),
        request.app.state.vault_service,
        request.app.state.clock,
        get_audit_logger(request),
    )


def get_transit_service(request: Request) -> TransitService:
    repository = SqlTransitKeyRepository(request.app.state.session_factory)
    return TransitService(
        repository,
        get_authz_service(),
        request.app.state.vault_service,
        request.app.state.clock,
        get_audit_logger(request),
    )


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
SessionServiceDependency = Annotated[SessionService, Depends(get_session_service)]
KvServiceDependency = Annotated[KvService, Depends(get_kv_service)]
TransitServiceDependency = Annotated[TransitService, Depends(get_transit_service)]
AuditRepositoryDependency = Annotated[SqlAuditRepository, Depends(get_audit_repository)]
BearerCredentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)]
