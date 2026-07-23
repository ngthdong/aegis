from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from aegis.api.dependencies import CurrentPrincipal, KvServiceDep, RequireVaultUnsealed

router = APIRouter(prefix="/v1/kv", tags=["kv"])


@router.put("/{path:path}", status_code=204)
async def write_secret(
    path: str,
    value: dict[str, Any],
    principal: CurrentPrincipal,
    kv: KvServiceDep,
    _vault_unsealed: RequireVaultUnsealed,
) -> None:
    kv.write(principal, path, value)


@router.get("/{path:path}")
async def read_secret(
    path: str,
    principal: CurrentPrincipal,
    kv: KvServiceDep,
    _vault_unsealed: RequireVaultUnsealed,
) -> dict[str, Any]:
    return kv.read(principal, path)


@router.delete("/{path:path}", status_code=204)
async def delete_secret(
    path: str,
    principal: CurrentPrincipal,
    kv: KvServiceDep,
    _vault_unsealed: RequireVaultUnsealed,
) -> None:
    kv.delete(principal, path)
