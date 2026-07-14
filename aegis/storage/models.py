from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, LargeBinary, String
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
