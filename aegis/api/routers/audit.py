from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query

from aegis.api.dependencies import AuditRepositoryDependency, CurrentPrincipal

router = APIRouter(prefix="/v1/audit", tags=["audit"])

MAX_LIMIT = 200
DEFAULT_LIMIT = 50


@router.get("")
async def list_audit_events(
    principal: CurrentPrincipal,
    audit_repository: AuditRepositoryDependency,
    principal_id: Annotated[
        str | None,
        Query(description="Defaults to your own principal id. Any other value returns 403."),
    ] = None,
    action: Annotated[str | None, Query(description="e.g. 'kv.write', 'transit.sign'")] = None,
    since: Annotated[datetime | None, Query(description="ISO-8601 timestamp, inclusive")] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    if principal_id is not None and principal_id != principal.user_id:
        raise HTTPException(status_code=403, detail="cannot query another principal's audit trail")

    effective_principal_id = principal_id or principal.user_id

    events = audit_repository.list_for_principal(
        effective_principal_id, action, since, limit, offset
    )

    return {
        "events": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "principal_id": e.principal_id,
                "action": e.action,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
                "outcome": e.outcome,
                "metadata": e.metadata,
            }
            for e in events
        ],
        "limit": limit,
        "offset": offset,
    }
