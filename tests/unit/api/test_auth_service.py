import pytest

from aegis.auth.repository import InMemoryUserRepository
from aegis.auth.service import AuthService, UsernameTaken, WeakPassword


@pytest.fixture
def auth_service() -> AuthService:
    return AuthService(InMemoryUserRepository())


def test_register_returns_a_user_id(auth_service: AuthService):
    user_id = auth_service.register("alice", "correct-horse-battery")
    assert isinstance(user_id, str)
    assert len(user_id) == 32


def test_register_rejects_duplicate_username(auth_service: AuthService):
    auth_service.register("alice", "correct-horse-battery")
    with pytest.raises(UsernameTaken):
        auth_service.register("alice", "a-different-password")


def test_register_rejects_short_password(auth_service: AuthService):
    with pytest.raises(WeakPassword):
        auth_service.register("bob", "short")


def test_weak_password_checked_before_username_uniqueness(auth_service: AuthService):
    auth_service.register("alice", "correct-horse-battery")
    with pytest.raises(WeakPassword):
        auth_service.register("alice", "short")
