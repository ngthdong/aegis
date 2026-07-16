from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from aegis.api.dependencies import AuthServiceDependency, RequireVaultUnsealed

router = APIRouter(prefix="/v1/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1)


class RegisterResponse(BaseModel):
    user_id: str


@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register(
    body: RegisterRequest,
    auth_service: AuthServiceDependency,
    _vault_unsealed: RequireVaultUnsealed,
) -> RegisterResponse:
    user_id = auth_service.register(body.username, body.password)
    return RegisterResponse(user_id=user_id)
