from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from aegis.auth.service import UsernameTaken, WeakPassword
from aegis.core.service import (
    InvalidPassphrase,
    VaultAlreadyInitialized,
    VaultNotInitialized,
)


class VaultSealedError(Exception):
    """
    Raised when an operation requires the vault to be unsealed.
    This is separate from VaultNotInitialized because a sealed vault and
    an uninitialized vault represent different operational states, even
    if both currently prevent the same operations.
    """


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(UsernameTaken)
    async def _username_taken(request: Request, exc: UsernameTaken) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(WeakPassword)
    async def _weak_password(request: Request, exc: WeakPassword) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(VaultAlreadyInitialized)
    async def _vault_already_initialized(
        request: Request, exc: VaultAlreadyInitialized
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(VaultNotInitialized)
    async def _vault_not_initialized(request: Request, exc: VaultNotInitialized) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(InvalidPassphrase)
    async def _invalid_passphrase(request: Request, exc: InvalidPassphrase) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": str(exc)})

    @app.exception_handler(VaultSealedError)
    async def _vault_sealed(request: Request, exc: VaultSealedError) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": str(exc)})
