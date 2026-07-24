from __future__ import annotations

import base64

from fastapi import APIRouter
from pydantic import BaseModel, Field

from aegis.api.dependencies import CurrentPrincipal, RequireVaultUnsealed, TransitServiceDep
from aegis.transit.models import TransitKeyType

router = APIRouter(prefix="/v1/transit/keys", tags=["transit"])


class CreateKeyRequest(BaseModel):
    key_type: TransitKeyType = "symmetric"


class CreateKeyResponse(BaseModel):
    name: str
    key_type: TransitKeyType


class EncryptRequest(BaseModel):
    plaintext: str = Field(description="base64-encoded plaintext bytes")


class EncryptResponse(BaseModel):
    ciphertext: str = Field(description="base64-encoded ciphertext blob")


class DecryptRequest(BaseModel):
    ciphertext: str = Field(description="base64-encoded ciphertext blob from /encrypt")


class DecryptResponse(BaseModel):
    plaintext: str = Field(description="base64-encoded plaintext bytes")


class SignRequest(BaseModel):
    message: str = Field(description="base64-encoded message bytes to sign")


class SignResponse(BaseModel):
    signature: str = Field(description="base64-encoded Ed25519 signature")


class VerifyRequest(BaseModel):
    message: str = Field(description="base64-encoded message bytes")
    signature: str = Field(description="base64-encoded Ed25519 signature to check")


class VerifyResponse(BaseModel):
    valid: bool


@router.post("/{name}", response_model=CreateKeyResponse, status_code=201)
async def create_key(
    name: str,
    principal: CurrentPrincipal,
    transit: TransitServiceDep,
    _vault_unsealed: RequireVaultUnsealed,
    body: CreateKeyRequest | None = None,
) -> CreateKeyResponse:
    key_type = body.key_type if body is not None else "symmetric"
    transit.create_key(principal, name, key_type=key_type)
    return CreateKeyResponse(name=name, key_type=key_type)


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


@router.post("/{name}/sign", response_model=SignResponse)
async def sign(
    name: str,
    body: SignRequest,
    principal: CurrentPrincipal,
    transit: TransitServiceDep,
    _vault_unsealed: RequireVaultUnsealed,
) -> SignResponse:
    message = base64.b64decode(body.message)
    signature = transit.sign(principal, name, message)
    return SignResponse(signature=signature)


@router.post("/{name}/verify", response_model=VerifyResponse)
async def verify(
    name: str,
    body: VerifyRequest,
    principal: CurrentPrincipal,
    transit: TransitServiceDep,
    _vault_unsealed: RequireVaultUnsealed,
) -> VerifyResponse:
    message = base64.b64decode(body.message)
    is_valid = transit.verify(principal, name, message, body.signature)
    return VerifyResponse(valid=is_valid)


@router.post("/{name}/disable", status_code=204)
async def disable(
    name: str,
    principal: CurrentPrincipal,
    transit: TransitServiceDep,
    _vault_unsealed: RequireVaultUnsealed,
) -> None:
    transit.disable_key(principal, name)


@router.delete("/{name}", status_code=204)
async def destroy(
    name: str,
    principal: CurrentPrincipal,
    transit: TransitServiceDep,
    _vault_unsealed: RequireVaultUnsealed,
) -> None:
    transit.destroy_key(principal, name)
