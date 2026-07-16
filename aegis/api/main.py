from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager

from alembic.migration import Engine
from fastapi import FastAPI

from aegis.api.routers import auth, health, vault
from aegis.common.errors import register_exception_handlers
from aegis.common.logging import configure_logging, get_logger
from aegis.config.settings import Settings, get_settings
from aegis.core.service import VaultService
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
        logger.info("shutdown")

    return lifespan


def create_app(settings: Settings | None = None, engine: Engine | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)
    engine = engine or create_sqlite_engine(settings)

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
    app.state.vault_service = VaultService(SqlVaultRepository(session_factory))

    app.include_router(health.router)
    app.include_router(vault.router)
    app.include_router(auth.router)

    register_exception_handlers(app)

    return app


app = create_app()
