from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from aegis.auth.models import User
from aegis.auth.password import hash_password, verify_password
from aegis.auth.repository import UserRepository
from aegis.auth.session_service import SessionService
from aegis.common.clock import Clock

MIN_PASSWORD_LENGTH = 12
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

_DUMMY_PASSWORD_HASH = hash_password("dummy-password-used-only-for-timing-uniformity")


class UsernameTaken(Exception):
    pass


class WeakPassword(Exception):
    pass


class InvalidCredentials(Exception):
    """
    Raised for both 'user does not exist' and 'password was wrong'
    """


class AccountLocked(Exception):
    def __init__(self, locked_until: datetime) -> None:
        self.locked_until = locked_until
        super().__init__(f"account locked until {locked_until.isoformat()}")


@dataclass(frozen=True, slots=True)
class LoginResult:
    token: str
    expires_at: datetime


class AuthService:
    def __init__(
        self,
        user_repository: UserRepository,
        session_service: SessionService,
        clock: Clock,
    ) -> None:
        self._user_repository = user_repository
        self._session_service = session_service
        self._clock = clock

    def register(self, username: str, password: str) -> str:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise WeakPassword(f"password must be at least {MIN_PASSWORD_LENGTH} characters")

        if self._user_repository.get_by_username(username) is not None:
            raise UsernameTaken(f"username '{username}' is already taken")

        user = User(
            id=uuid.uuid4().hex,
            username=username,
            password_hash=hash_password(password),
            failed_login_count=0,
            locked_until=None,
            created_at=datetime.now(UTC),
        )
        self._user_repository.save(user)
        return user.id

    def login(self, username: str, password: str) -> LoginResult:
        user = self._user_repository.get_by_username(username)

        if user is None:
            verify_password(password, _DUMMY_PASSWORD_HASH)
            raise InvalidCredentials("invalid username or password")

        now = self._clock.now()
        if user.locked_until is not None and now < user.locked_until:
            raise AccountLocked(user.locked_until)

        if not verify_password(password, user.password_hash):
            new_count = user.failed_login_count + 1
            locked_until = (
                now + LOCKOUT_DURATION if new_count >= MAX_FAILED_LOGIN_ATTEMPTS else None
            )
            self._user_repository.update_login_state(user.id, new_count, locked_until)
            if locked_until is not None:
                raise AccountLocked(locked_until)
            raise InvalidCredentials("invalid username or password")

        if user.failed_login_count != 0 or user.locked_until is not None:
            self._user_repository.update_login_state(user.id, 0, None)

        token = self._session_service.create(user.id, user.username)
        expires_at = self._clock.now() + self._session_service.ttl
        return LoginResult(token=token, expires_at=expires_at)

    def logout(self, token: str) -> None:
        self._session_service.revoke(token)
