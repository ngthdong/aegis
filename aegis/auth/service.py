from __future__ import annotations

import uuid
from datetime import UTC, datetime

from aegis.auth.models import User
from aegis.auth.password import hash_password
from aegis.auth.repository import UserRepository

MIN_PASSWORD_LENGTH = 12


class UsernameTaken(Exception):
    pass


class WeakPassword(Exception):
    pass


class AuthService:
    def __init__(self, repository: UserRepository) -> None:
        self._repository = repository

    def register(self, username: str, password: str) -> str:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise WeakPassword(f"password must be at least {MIN_PASSWORD_LENGTH} characters")

        if self._repository.get_by_username(username) is not None:
            raise UsernameTaken(f"username '{username}' is already taken")

        user = User(
            id=uuid.uuid4().hex,
            username=username,
            password_hash=hash_password(password),
            failed_login_count=0,
            locked_until=None,
            created_at=datetime.now(UTC),
        )
        self._repository.save(user)
        return user.id
