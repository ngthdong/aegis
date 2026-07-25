from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from aegis.api.dependencies import (
    AuthServiceDependency,
    BearerCredentials,
    CurrentPrincipal,
    RequireVaultUnsealed,
    SessionServiceDependency,
)
from aegis.auth.session_service import SessionExpired, SessionNotFound, SessionRevoked
from aegis.common.errors import InvalidSessionError

router = APIRouter(prefix="/v1/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1)


class RegisterResponse(BaseModel):
    user_id: str


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1)


class LoginResponse(BaseModel):
    token: str
    expires_at: str


class MeResponse(BaseModel):
    user_id: str
    username: str


@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register(
    body: RegisterRequest,
    auth_service: AuthServiceDependency,
    _vault_unsealed: RequireVaultUnsealed,
) -> RegisterResponse:
    user_id = auth_service.register(body.username, body.password)
    return RegisterResponse(user_id=user_id)


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, auth_service: AuthServiceDependency) -> LoginResponse:
    result = auth_service.login(body.username, body.password)
    return LoginResponse(token=result.token, expires_at=result.expires_at.isoformat())


@router.post("/logout", status_code=204)
async def logout(
    credentials: BearerCredentials,
    session_service: SessionServiceDependency,
) -> None:
    if credentials is None:
        raise InvalidSessionError("missing bearer token")

    try:
        session_service.validate(credentials.credentials)
    except (SessionNotFound, SessionExpired, SessionRevoked) as exc:
        raise InvalidSessionError("invalid or expired session") from exc

    session_service.revoke(credentials.credentials)


@router.get("/me", response_model=MeResponse)
async def me(principal: CurrentPrincipal) -> MeResponse:
    return MeResponse(user_id=principal.user_id, username=principal.username)
