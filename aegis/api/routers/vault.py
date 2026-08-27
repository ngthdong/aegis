from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from aegis.api.dependencies import (
    RequireAdmin,
    UserRepositoryDependency,
    VaultRepositoryDependency,
    VaultServiceDependency,
)
from aegis.auth.models import ROLE_ADMIN, User
from aegis.auth.password import hash_password
from aegis.auth.service import UsernameTaken, validate_password_strength

router = APIRouter(prefix="/v1/vault", tags=["vault"])


class InitRequest(BaseModel):
    passphrase: str = Field(min_length=1, description="Master passphrase used to protect the DEK")
    admin_username: str = Field(min_length=1, max_length=64, description="Initial admin username")
    admin_password: str = Field(min_length=1, description="Initial admin password")


class UnsealRequest(BaseModel):
    passphrase: str = Field(min_length=1)


class StatusResponse(BaseModel):
    status: str


class SealResponse(BaseModel):
    status: Literal["sealed"] = "sealed"


@router.post("/init", response_model=StatusResponse)
async def init_vault(
    body: InitRequest,
    vault: VaultServiceDependency,
    vault_repository: VaultRepositoryDependency,
    user_repository: UserRepositoryDependency,
) -> StatusResponse:
    validate_password_strength(body.admin_password)
    if user_repository.get_by_username(body.admin_username) is not None:
        raise UsernameTaken(f"username '{body.admin_username}' is already taken")

    vault.initialize(body.passphrase)

    try:
        admin = User(
            id=uuid.uuid4().hex,
            username=body.admin_username,
            password_hash=hash_password(body.admin_password),
            failed_login_count=0,
            locked_until=None,
            created_at=datetime.now(UTC),
            role=ROLE_ADMIN,
        )
        user_repository.save(admin)
    except Exception:
        vault_repository.delete()
        raise

    return StatusResponse(status=vault.status().value)


@router.post("/unseal", response_model=StatusResponse)
async def unseal_vault(body: UnsealRequest, vault: VaultServiceDependency) -> StatusResponse:
    vault.unseal(body.passphrase)
    return StatusResponse(status=vault.status().value)


@router.post("/seal", response_model=SealResponse)
async def seal_vault(vault: VaultServiceDependency, _admin: RequireAdmin) -> SealResponse:
    vault.seal()
    return SealResponse()


@router.get("/status", response_model=StatusResponse)
async def vault_status(vault: VaultServiceDependency) -> StatusResponse:
    return StatusResponse(status=vault.status().value)
