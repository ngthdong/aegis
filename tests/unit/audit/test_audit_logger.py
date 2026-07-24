from aegis.audit.logger import AuditLogger
from aegis.audit.repository import InMemoryAuditRepository
from aegis.common.clock import FakeClock


def test_record_persists_all_fields():
    repo = InMemoryAuditRepository()
    logger = AuditLogger(repo, FakeClock())
    logger.record(
        principal_id="user-1",
        action="kv.write",
        resource_type="secret",
        resource_id="db/password",
        outcome="success",
        metadata={"foo": "bar"},
    )
    event = repo.events[0]
    assert event.principal_id == "user-1"
    assert event.metadata == {"foo": "bar"}


def test_record_defaults_metadata_to_empty_dict_not_none():
    repo = InMemoryAuditRepository()
    logger = AuditLogger(repo, FakeClock())
    logger.record("user-1", "kv.read", "secret", "x", "success", metadata=None)
    assert repo.events[0].metadata == {}


def test_each_record_call_gets_a_unique_id():
    repo = InMemoryAuditRepository()
    logger = AuditLogger(repo, FakeClock())
    logger.record("u", "kv.read", "secret", "a", "success")
    logger.record("u", "kv.read", "secret", "b", "success")
    assert repo.events[0].id != repo.events[1].id


def test_timestamp_comes_from_the_injected_clock_not_wall_time():
    from datetime import UTC, datetime

    fixed_time = datetime(2030, 1, 1, tzinfo=UTC)
    clock = FakeClock(start=fixed_time)
    repo = InMemoryAuditRepository()
    logger = AuditLogger(repo, clock)
    logger.record("u", "kv.read", "secret", "a", "success")
    assert repo.events[0].timestamp == fixed_time
