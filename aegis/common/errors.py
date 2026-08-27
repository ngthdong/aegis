from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from aegis.auth.service import AccountLocked, InvalidCredentials, UsernameTaken, WeakPassword
from aegis.auth.session_service import SessionExpired, SessionNotFound, SessionRevoked
from aegis.authz.service import PermissionDenied
from aegis.core.service import (
    InvalidPassphrase,
    VaultAlreadyInitialized,
    VaultAlreadySealed,
    VaultNotInitialized,
)
from aegis.kv.service import SecretCorrupted, SecretNotFound
from aegis.transit.service import (
    InvalidMessageType,
    TransitDecryptionFailed,
    TransitKeyAlreadyExists,
    TransitKeyDestroyed,
    TransitKeyDisabled,
    TransitKeyNotFound,
    TransitKeyVersionNotFound,
    WrongKeyType,
)


class VaultSealedError(Exception):
    """
    Raised when an operation requires the vault to be unsealed.
    This is separate from VaultNotInitialized because a sealed vault and
    an uninitialized vault represent different operational states, even
    if both currently prevent the same operations.
    """


class InvalidSessionError(Exception):
    """
    Raised by get_current_principal for any of: missing token, token
    not found, revoked, or expired.
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

    @app.exception_handler(VaultAlreadySealed)
    async def _vault_already_sealed(request: Request, exc: VaultAlreadySealed) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(InvalidPassphrase)
    async def _invalid_passphrase(request: Request, exc: InvalidPassphrase) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": str(exc)})

    @app.exception_handler(VaultSealedError)
    async def _vault_sealed(request: Request, exc: VaultSealedError) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": str(exc)})

    @app.exception_handler(InvalidCredentials)
    async def _invalid_credentials(request: Request, exc: InvalidCredentials) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": str(exc)})

    @app.exception_handler(AccountLocked)
    async def _account_locked(request: Request, exc: AccountLocked) -> JSONResponse:
        return JSONResponse(
            status_code=423,
            content={"detail": str(exc), "locked_until": exc.locked_until.isoformat()},
        )

    @app.exception_handler(InvalidSessionError)
    async def _invalid_session(request: Request, exc: InvalidSessionError) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": str(exc)})

    @app.exception_handler(SessionNotFound)
    async def _session_not_found(request: Request, exc: SessionNotFound) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": "invalid or expired session"})

    @app.exception_handler(SessionExpired)
    async def _session_expired(request: Request, exc: SessionExpired) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": "invalid or expired session"})

    @app.exception_handler(SessionRevoked)
    async def _session_revoked(request: Request, exc: SessionRevoked) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": "invalid or expired session"})

    @app.exception_handler(PermissionDenied)
    async def _permission_denied(request: Request, exc: PermissionDenied) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(SecretNotFound)
    async def _secret_not_found(request: Request, exc: SecretNotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(SecretCorrupted)
    async def _secret_corrupted(request: Request, exc: SecretCorrupted) -> JSONResponse:
        return JSONResponse(
            status_code=500, content={"detail": "secret data integrity check failed"}
        )

    @app.exception_handler(TransitKeyNotFound)
    async def _transit_key_not_found(request: Request, exc: TransitKeyNotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(TransitKeyAlreadyExists)
    async def _transit_key_already_exists(
        request: Request, exc: TransitKeyAlreadyExists
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(TransitKeyDisabled)
    async def _transit_key_disabled(request: Request, exc: TransitKeyDisabled) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(TransitKeyDestroyed)
    async def _transit_key_destroyed(request: Request, exc: TransitKeyDestroyed) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(WrongKeyType)
    async def _wrong_key_type(request: Request, exc: WrongKeyType) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(TransitDecryptionFailed)
    async def _transit_decryption_failed(
        request: Request, exc: TransitDecryptionFailed
    ) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(TransitKeyVersionNotFound)
    async def _transit_key_version_not_found(
        request: Request, exc: TransitKeyVersionNotFound
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(InvalidMessageType)
    async def _invalid_message_type(request: Request, exc: InvalidMessageType) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})
