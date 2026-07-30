from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class VaultMetaRow(Base):
    __tablename__ = "vault_meta"
    __table_args__ = (CheckConstraint("id = 1", name="vault_meta_singleton"),)

    id: Mapped[int] = mapped_column(primary_key=True, default=1)

    kdf_salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    kdf_time_cost: Mapped[int] = mapped_column(nullable=False)
    kdf_memory_cost_kib: Mapped[int] = mapped_column(nullable=False)
    kdf_parallelism: Mapped[int] = mapped_column(nullable=False)

    dek_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    dek_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    initialized_at: Mapped[str] = mapped_column(String, nullable=False)

    @property
    def initialized_at_dt(self) -> datetime:
        return datetime.fromisoformat(self.initialized_at)


class SessionRow(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    username: Mapped[str] = mapped_column(String, nullable=False)
    token_hash: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)

    created_at: Mapped[str] = mapped_column(String, nullable=False)
    expires_at: Mapped[str] = mapped_column(String, nullable=False)
    revoked_at: Mapped[str | None] = mapped_column(String, nullable=True)


class UserRow(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True)  # uuid4 hex
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)

    failed_login_count: Mapped[int] = mapped_column(nullable=False, default=0)
    locked_until: Mapped[str | None] = mapped_column(String, nullable=True)

    created_at: Mapped[str] = mapped_column(String, nullable=False)

    @property
    def created_at_dt(self) -> datetime:
        return datetime.fromisoformat(self.created_at)


class SecretRow(Base):
    __tablename__ = "secrets"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    path: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    owner_id: Mapped[str] = mapped_column(String, nullable=False, index=True)

    current_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )

    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)

    @property
    def created_at_dt(self) -> datetime:
        return datetime.fromisoformat(self.created_at)


class SecretVersionRow(Base):
    __tablename__ = "secret_versions"
    __table_args__ = (
        UniqueConstraint("secret_id", "version", name="uq_secret_versions_secret_id_version"),
        CheckConstraint("version >= 1", name="ck_secret_versions_version_positive"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True)
    secret_id: Mapped[str] = mapped_column(
        String, ForeignKey("secrets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)

    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    created_at: Mapped[str] = mapped_column(String, nullable=False)


class AuditLogRow(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp: Mapped[str] = mapped_column(String, nullable=False, index=True)
    principal_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    action: Mapped[str] = mapped_column(String, nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String, nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String, nullable=True)
    outcome: Mapped[str] = mapped_column(String, nullable=False)
    metadata_json: Mapped[str] = mapped_column(String, nullable=False, default="{}")


class TransitKeyRow(Base):
    __tablename__ = "transit_keys"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    owner_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    algorithm: Mapped[str] = mapped_column(String, nullable=False, default="AES-256-GCM")

    key_type: Mapped[str] = mapped_column(String, nullable=False, default="symmetric")

    key_nonce: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    wrapped_key_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    public_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    disabled: Mapped[bool] = mapped_column(nullable=False, default=False)

    destroyed_at: Mapped[str | None] = mapped_column(String, nullable=True)

    created_at: Mapped[str] = mapped_column(String, nullable=False)
