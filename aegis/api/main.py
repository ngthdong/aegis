from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager

from fastapi import FastAPI, Response
from sqlalchemy import Engine

from aegis.api.middleware import register_middleware
from aegis.api.routers import audit, auth, health, kv, transit, vault
from aegis.common.clock import Clock, SystemClock
from aegis.common.errors import register_exception_handlers
from aegis.common.logging import configure_logging, get_logger
from aegis.common.metrics import create_metrics, render_metrics
from aegis.config.settings import Settings, get_settings
from aegis.core.service import VaultService
from aegis.core.state import VaultState
from aegis.storage.db import create_sqlite_engine, get_sessionmaker
from aegis.storage.models import Base
from aegis.storage.repository import SqlVaultRepository

logger = get_logger(__name__)


def _build_lifespan(
    settings: Settings,
    engine: Engine,
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        logger.info(
            "startup",
            environment=settings.environment,
            log_level=settings.log_level.value,
        )
        yield
        engine.dispose()
        logger.info("shutdown")

    return lifespan


def create_app(
    settings: Settings | None = None, engine: Engine | None = None, clock: Clock | None = None
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)
    engine = engine or create_sqlite_engine(settings)
    clock = clock or SystemClock()

    Base.metadata.create_all(engine)

    session_factory = get_sessionmaker(engine)

    app = FastAPI(
        title=settings.app_name,
        description="Secret Management & Cryptographic Service",
        version="0.1.0",
        lifespan=_build_lifespan(settings, engine),
    )

    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.clock = clock
    app.state.metrics = create_metrics()
    app.state.vault_service = VaultService(SqlVaultRepository(session_factory))

    app.include_router(health.router)
    app.include_router(vault.router)
    app.include_router(auth.router)
    app.include_router(kv.router)
    app.include_router(transit.router)
    app.include_router(audit.router)

    register_middleware(app)
    register_exception_handlers(app)

    @app.get("/metrics", include_in_schema=False)
    async def metrics_endpoint() -> Response:
        app_metrics = app.state.metrics
        app_metrics.vault_sealed.set(
            0 if app.state.vault_service.status() == VaultState.UNSEALED else 1
        )
        body, content_type = render_metrics(app_metrics)
        return Response(content=body, media_type=content_type)

    return app


app = create_app()
