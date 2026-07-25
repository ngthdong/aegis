from __future__ import annotations

from fastapi import APIRouter, Request, Response
from sqlalchemy import text

from aegis.common.logging import get_logger
from aegis.core.state import VaultState

router = APIRouter(tags=["health"])
logger = get_logger(__name__)


@router.get("/health")
async def liveness() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
async def readiness(request: Request, response: Response) -> dict[str, object]:
    checks: dict[str, bool] = {}

    try:
        session_factory = request.app.state.session_factory
        with session_factory() as session:
            session.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception:
        logger.warning("readyz.database_check_failed")
        checks["database"] = False

    vault_status = request.app.state.vault_service.status()
    checks["vault_unsealed"] = vault_status == VaultState.UNSEALED

    all_ready = all(checks.values())
    if not all_ready:
        response.status_code = 503

    return {"status": "ok" if all_ready else "not ready", "checks": checks}
