from __future__ import annotations

from datetime import datetime
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from aegis.auth.models import User
from aegis.storage.models import UserRow
from aegis.storage.unit_of_work import UnitOfWork


class UserRepository(Protocol):
    def get_by_username(self, username: str) -> User | None: ...
    def save(self, user: User) -> None: ...


class InMemoryUserRepository:
    def __init__(self) -> None:
        self._users: dict[str, User] = {}  # keyed by username

    def get_by_username(self, username: str) -> User | None:
        return self._users.get(username)

    def save(self, user: User) -> None:
        self._users[user.username] = user


class SqlUserRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def get_by_username(self, username: str) -> User | None:
        with UnitOfWork(self._session_factory) as uow:
            row = uow.session.execute(
                select(UserRow).where(UserRow.username == username)
            ).scalar_one_or_none()
            if row is None:
                return None
            return _row_to_user(row)

    def save(self, user: User) -> None:
        with UnitOfWork(self._session_factory) as uow:
            row = UserRow(
                id=user.id,
                username=user.username,
                password_hash=user.password_hash,
                failed_login_count=user.failed_login_count,
                locked_until=user.locked_until.isoformat() if user.locked_until else None,
                created_at=user.created_at.isoformat(),
            )
            uow.session.add(row)
            uow.commit()


def _row_to_user(row: UserRow) -> User:
    return User(
        id=row.id,
        username=row.username,
        password_hash=row.password_hash,
        failed_login_count=row.failed_login_count,
        locked_until=datetime.fromisoformat(row.locked_until) if row.locked_until else None,
        created_at=row.created_at_dt,
    )
