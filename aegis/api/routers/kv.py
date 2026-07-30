from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query

from aegis.api.dependencies import CurrentPrincipal, KvServiceDependency, RequireVaultUnsealed

router = APIRouter(prefix="/v1/kv", tags=["kv"])


@router.put("/{path:path}", status_code=204)
async def write_secret(
    path: str,
    value: dict[str, Any],
    principal: CurrentPrincipal,
    kv: KvServiceDependency,
    _vault_unsealed: RequireVaultUnsealed,
) -> None:
    kv.write(principal, path, value)


@router.get("/{path:path}")
async def read_secret(
    path: str,
    principal: CurrentPrincipal,
    kv: KvServiceDependency,
    _vault_unsealed: RequireVaultUnsealed,
    version: Annotated[int | None, Query(ge=1)] = None,
) -> dict[str, Any]:
    return kv.read(principal, path, version)


@router.delete("/{path:path}", status_code=204)
async def delete_secret(
    path: str,
    principal: CurrentPrincipal,
    kv: KvServiceDependency,
    _vault_unsealed: RequireVaultUnsealed,
) -> None:
    kv.delete(principal, path)
