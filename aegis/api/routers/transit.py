from __future__ import annotations

import base64
from enum import StrEnum
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from aegis.api.dependencies import CurrentPrincipal, RequireVaultUnsealed, TransitServiceDependency
from aegis.transit.models import HashAlgorithm, MessageType

router = APIRouter(prefix="/v1/transit/keys", tags=["transit"])

KeyType = Literal["symmetric", "asymmetric_sign"]


class KeyUsage(StrEnum):
    ENCRYPT_DECRYPT = "ENCRYPT_DECRYPT"
    SIGN_VERIFY = "SIGN_VERIFY"


_KEY_USAGE_TO_KEY_TYPE: dict[KeyUsage, KeyType] = {
    KeyUsage.ENCRYPT_DECRYPT: "symmetric",
    KeyUsage.SIGN_VERIFY: "asymmetric_sign",
}


class CreateKeyRequest(BaseModel):
    key_usage: KeyUsage = KeyUsage.ENCRYPT_DECRYPT


class CreateKeyResponse(BaseModel):
    name: str
    key_type: KeyUsage


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
    message_type: MessageType = "RAW"
    hash_algorithm: HashAlgorithm | None = None


class SignResponse(BaseModel):
    signature: str = Field(description="base64-encoded Ed25519 signature")


class VerifyRequest(BaseModel):
    message: str = Field(description="base64-encoded message bytes")
    signature: str = Field(description="base64-encoded Ed25519 signature to check")
    message_type: MessageType = "RAW"
    hash_algorithm: HashAlgorithm | None = None


class VerifyResponse(BaseModel):
    valid: bool
    signature_valid: bool
    signing_algorithm: str


class RotateKeyResponse(BaseModel):
    current_version: int


@router.post(
    "/{name}",
    response_model=CreateKeyResponse,
    status_code=201,
    summary="Create a named Transit key",
)
async def create_key(
    name: str,
    principal: CurrentPrincipal,
    transit: TransitServiceDependency,
    _vault_unsealed: RequireVaultUnsealed,
    body: CreateKeyRequest | None = None,
) -> CreateKeyResponse:
    key_usage = body.key_usage if body is not None else KeyUsage.ENCRYPT_DECRYPT
    key_type = _KEY_USAGE_TO_KEY_TYPE[key_usage]
    transit.create_key(principal, name, key_type=key_type)
    return CreateKeyResponse(name=name, key_type=key_usage)


@router.post(
    "/{name}/encrypt",
    response_model=EncryptResponse,
    summary="Encrypt plaintext under a symmetric (ENCRYPT_DECRYPT) key",
)
async def encrypt(
    name: str,
    body: EncryptRequest,
    principal: CurrentPrincipal,
    transit: TransitServiceDependency,
    _vault_unsealed: RequireVaultUnsealed,
) -> EncryptResponse:
    plaintext = base64.b64decode(body.plaintext)
    ciphertext_b64 = transit.encrypt(principal, name, plaintext)
    return EncryptResponse(ciphertext=ciphertext_b64)


@router.post(
    "/{name}/decrypt",
    response_model=DecryptResponse,
    summary="Decrypt a ciphertext blob produced by /encrypt",
)
async def decrypt(
    name: str,
    body: DecryptRequest,
    principal: CurrentPrincipal,
    transit: TransitServiceDependency,
    _vault_unsealed: RequireVaultUnsealed,
) -> DecryptResponse:
    plaintext = transit.decrypt(principal, name, body.ciphertext)
    return DecryptResponse(plaintext=base64.b64encode(plaintext).decode("ascii"))


@router.post(
    "/{name}/sign",
    response_model=SignResponse,
    summary="Sign a message or digest under an asymmetric (SIGN_VERIFY) key",
)
async def sign(
    name: str,
    body: SignRequest,
    principal: CurrentPrincipal,
    transit: TransitServiceDependency,
    _vault_unsealed: RequireVaultUnsealed,
) -> SignResponse:
    message = base64.b64decode(body.message)
    signature = transit.sign(
        principal,
        name,
        message,
        message_type=body.message_type,
        hash_algorithm=body.hash_algorithm,
    )
    return SignResponse(signature=signature)


@router.post(
    "/{name}/verify",
    response_model=VerifyResponse,
    summary="Verify a signature against a named key",
)
async def verify(
    name: str,
    body: VerifyRequest,
    principal: CurrentPrincipal,
    transit: TransitServiceDependency,
    _vault_unsealed: RequireVaultUnsealed,
) -> VerifyResponse:
    message = base64.b64decode(body.message)
    result = transit.verify(
        principal,
        name,
        message,
        body.signature,
        message_type=body.message_type,
        hash_algorithm=body.hash_algorithm,
    )
    return VerifyResponse(
        valid=result.signature_valid,
        signature_valid=result.signature_valid,
        signing_algorithm=result.signing_algorithm,
    )


@router.post(
    "/{name}/rotate",
    response_model=RotateKeyResponse,
    summary="Rotate a key generating fresh, independent key material as a new version",
)
async def rotate_key(
    name: str,
    principal: CurrentPrincipal,
    transit: TransitServiceDependency,
    _vault_unsealed: RequireVaultUnsealed,
) -> dict[str, int]:
    version = transit.rotate_key(principal, name)
    return RotateKeyResponse(current_version=version)


@router.post(
    "/{name}/disable",
    status_code=204,
    summary="Disable a key (blocks new encrypt/sign; decrypt/verify remain allowed)",
)
async def disable(
    name: str,
    principal: CurrentPrincipal,
    transit: TransitServiceDependency,
    _vault_unsealed: RequireVaultUnsealed,
) -> None:
    transit.disable_key(principal, name)


@router.delete(
    "/{name}",
    status_code=204,
    summary="Destroy a key permanently (irreversible; wipes all key material)",
)
async def destroy(
    name: str,
    principal: CurrentPrincipal,
    transit: TransitServiceDependency,
    _vault_unsealed: RequireVaultUnsealed,
) -> None:
    transit.destroy_key(principal, name)
