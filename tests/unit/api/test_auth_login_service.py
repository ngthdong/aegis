from datetime import timedelta

import pytest

from aegis.auth.repository import InMemoryUserRepository
from aegis.auth.service import (
    MAX_FAILED_LOGIN_ATTEMPTS,
    AccountLocked,
    AuthService,
    InvalidCredentials,
)
from aegis.auth.session_repository import InMemorySessionRepository
from aegis.auth.session_service import SessionRevoked, SessionService
from aegis.common.clock import FakeClock
from aegis.common.metrics import create_metrics

VALID_PASSWORD = "correct-horse-battery"


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def auth_service(clock: FakeClock) -> AuthService:
    user_repo = InMemoryUserRepository()
    session_service = SessionService(InMemorySessionRepository(), clock)
    return AuthService(user_repo, session_service, clock, create_metrics())


def test_login_with_correct_password_succeeds(auth_service: AuthService):
    auth_service.register("alice", VALID_PASSWORD)
    result = auth_service.login("alice", VALID_PASSWORD)
    assert isinstance(result.token, str)
    assert len(result.token) > 20


def test_login_with_wrong_password_raises_invalid_credentials(auth_service: AuthService):
    auth_service.register("alice", VALID_PASSWORD)
    with pytest.raises(InvalidCredentials):
        auth_service.login("alice", "wrong-password")


def test_login_with_unknown_username_raises_invalid_credentials(auth_service: AuthService):
    with pytest.raises(InvalidCredentials):
        auth_service.login("nobody-registered-this-username", "whatever")


def test_account_locks_after_max_failed_attempts(auth_service: AuthService):
    auth_service.register("alice", VALID_PASSWORD)

    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS - 1):
        with pytest.raises(InvalidCredentials):
            auth_service.login("alice", "wrong-password")

    with pytest.raises(AccountLocked):
        auth_service.login("alice", "wrong-password")


def test_correct_password_rejected_while_locked(auth_service: AuthService):
    auth_service.register("alice", VALID_PASSWORD)
    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        with pytest.raises((InvalidCredentials, AccountLocked)):
            auth_service.login("alice", "wrong-password")

    with pytest.raises(AccountLocked):
        auth_service.login("alice", VALID_PASSWORD)


def test_lockout_expires_after_window_elapses(auth_service: AuthService, clock: FakeClock):
    auth_service.register("alice", VALID_PASSWORD)
    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        with pytest.raises((InvalidCredentials, AccountLocked)):
            auth_service.login("alice", "wrong-password")

    clock.advance(timedelta(minutes=15, seconds=1))

    result = auth_service.login("alice", VALID_PASSWORD)
    assert result.token


def test_successful_login_resets_failed_counter(auth_service: AuthService):
    auth_service.register("alice", VALID_PASSWORD)

    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS - 2):
        with pytest.raises(InvalidCredentials):
            auth_service.login("alice", "wrong-password")

    auth_service.login("alice", VALID_PASSWORD)  # resets the counter

    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS - 1):
        with pytest.raises(InvalidCredentials):
            auth_service.login("alice", "wrong-password")


def test_logout_revokes_the_session(auth_service: AuthService):
    auth_service.register("alice", VALID_PASSWORD)
    result = auth_service.login("alice", VALID_PASSWORD)

    auth_service.logout(result.token)

    with pytest.raises(SessionRevoked):
        auth_service._session_service.validate(result.token)  # type: ignore[attr-defined]
