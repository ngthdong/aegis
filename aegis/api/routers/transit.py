from __future__ import annotations

import base64

from fastapi import APIRouter
from pydantic import BaseModel, Field

from aegis.api.dependencies import CurrentPrincipal, RequireVaultUnsealed, TransitServiceDep

router = APIRouter(prefix="/v1/transit/keys", tags=["transit"])


class CreateKeyResponse(BaseModel):
    name: str


class EncryptRequest(BaseModel):
    plaintext: str = Field(description="base64-encoded plaintext bytes")


class EncryptResponse(BaseModel):
    ciphertext: str = Field(description="base64-encoded ciphertext blob")


class DecryptRequest(BaseModel):
    ciphertext: str = Field(description="base64-encoded ciphertext blob from /encrypt")


class DecryptResponse(BaseModel):
    plaintext: str = Field(description="base64-encoded plaintext bytes")


@router.post("/{name}", response_model=CreateKeyResponse, status_code=201)
async def create_key(
    name: str,
    principal: CurrentPrincipal,
    transit: TransitServiceDep,
    _vault_unsealed: RequireVaultUnsealed,
) -> CreateKeyResponse:
    transit.create_key(principal, name)
    return CreateKeyResponse(name=name)


@router.post("/{name}/encrypt", response_model=EncryptResponse)
async def encrypt(
    name: str,
    body: EncryptRequest,
    principal: CurrentPrincipal,
    transit: TransitServiceDep,
    _vault_unsealed: RequireVaultUnsealed,
) -> EncryptResponse:
    plaintext = base64.b64decode(body.plaintext)
    ciphertext_b64 = transit.encrypt(principal, name, plaintext)
    return EncryptResponse(ciphertext=ciphertext_b64)


@router.post("/{name}/decrypt", response_model=DecryptResponse)
async def decrypt(
    name: str,
    body: DecryptRequest,
    principal: CurrentPrincipal,
    transit: TransitServiceDep,
    _vault_unsealed: RequireVaultUnsealed,
) -> DecryptResponse:
    plaintext = transit.decrypt(principal, name, body.ciphertext)
    return DecryptResponse(plaintext=base64.b64encode(plaintext).decode("ascii"))
