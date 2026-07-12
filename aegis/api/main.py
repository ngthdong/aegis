from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from aegis.api.routers import health
from aegis.common.logging import configure_logging, get_logger
from aegis.config.settings import Settings, get_settings

logger = get_logger(__name__)


def _build_lifespan(settings: Settings) -> None:
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


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)

    app = FastAPI(
        title=settings.app_name,
        description="Secret Management & Cryptographic Service",
        version="0.1.0",
        lifespan=_build_lifespan(settings),
    )

    app.state.settings = settings

    app.include_router(health.router)

    return app


app = create_app()
