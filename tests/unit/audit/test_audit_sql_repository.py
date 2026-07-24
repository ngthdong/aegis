from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from aegis.audit.models import AuditEvent
from aegis.audit.repository import AuditRepository, SqlAuditRepository
from aegis.storage.db import create_memory_engine
from aegis.storage.models import AuditLogRow, Base


@pytest.fixture
def session_factory() -> sessionmaker:
    engine = create_memory_engine()
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def test_save_persists_a_real_row_with_metadata_as_json_text(session_factory: sessionmaker):
    repo = SqlAuditRepository(session_factory)
    event = AuditEvent(
        id="evt-1",
        timestamp=datetime(2030, 1, 1, tzinfo=UTC),
        principal_id="user-1",
        action="kv.write",
        resource_type="secret",
        resource_id="db/password",
        outcome="success",
        metadata={"reason": "not_found"},
    )
    repo.save(event)

    with session_factory() as session:
        row = session.execute(select(AuditLogRow).where(AuditLogRow.id == "evt-1")).scalar_one()
        assert row.outcome == "success"
        assert row.metadata_json == '{"reason": "not_found"}'


def test_audit_log_is_genuinely_append_only():
    assert not hasattr(AuditRepository, "update")
    assert not hasattr(AuditRepository, "delete")
