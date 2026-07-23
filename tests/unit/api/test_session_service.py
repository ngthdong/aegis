from datetime import timedelta

import pytest

from aegis.auth.session_repository import InMemorySessionRepository
from aegis.auth.session_service import (
    SessionExpired,
    SessionNotFound,
    SessionRevoked,
    SessionService,
)
from aegis.common.clock import FakeClock


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def session_service(clock: FakeClock) -> SessionService:
    return SessionService(InMemorySessionRepository(), clock, ttl=timedelta(hours=1))


def test_create_returns_a_usable_token(session_service: SessionService):
    token = session_service.create("user-1", "alice")
    principal = session_service.validate(token)
    assert principal.user_id == "user-1"
    assert principal.username == "alice"


def test_validate_rejects_unknown_token(session_service: SessionService):
    with pytest.raises(SessionNotFound):
        session_service.validate("this-token-was-never-issued")


def test_validate_rejects_expired_token(session_service: SessionService, clock: FakeClock):
    token = session_service.create("user-1", "alice")
    clock.advance(timedelta(hours=1, seconds=1))
    with pytest.raises(SessionExpired):
        session_service.validate(token)


def test_token_still_valid_one_second_before_expiry(
    session_service: SessionService, clock: FakeClock
):
    token = session_service.create("user-1", "alice")
    clock.advance(timedelta(hours=1) - timedelta(seconds=1))
    session_service.validate(token)  # must not raise


def test_revoke_invalidates_the_token_immediately(session_service: SessionService):
    token = session_service.create("user-1", "alice")
    session_service.revoke(token)
    with pytest.raises(SessionRevoked):
        session_service.validate(token)


def test_two_sessions_for_same_user_have_different_tokens(session_service: SessionService):
    token_a = session_service.create("user-1", "alice")
    token_b = session_service.create("user-1", "alice")
    assert token_a != token_b
    # Revoking one must not affect the other.
    session_service.revoke(token_a)
    session_service.validate(token_b)  # must not raise
