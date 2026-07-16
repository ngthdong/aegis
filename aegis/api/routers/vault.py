from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from aegis.api.dependencies import VaultServiceDependency

router = APIRouter(prefix="/v1/vault", tags=["vault"])


class InitRequest(BaseModel):
    passphrase: str = Field(min_length=1)


class UnsealRequest(BaseModel):
    passphrase: str = Field(min_length=1)


class StatusResponse(BaseModel):
    status: str


@router.post("/init", response_model=StatusResponse)
async def init_vault(body: InitRequest, vault: VaultServiceDependency) -> StatusResponse:
    vault.initialize(body.passphrase)
    return StatusResponse(status=vault.status().value)


@router.post("/unseal", response_model=StatusResponse)
async def unseal_vault(body: UnsealRequest, vault: VaultServiceDependency) -> StatusResponse:
    vault.unseal(body.passphrase)
    return StatusResponse(status=vault.status().value)


@router.post("/seal", response_model=StatusResponse)
async def seal_vault(vault: VaultServiceDependency) -> StatusResponse:
    vault.seal()
    return StatusResponse(status=vault.status().value)


@router.get("/status", response_model=StatusResponse)
async def vault_status(vault: VaultServiceDependency) -> StatusResponse:
    return StatusResponse(status=vault.status().value)
