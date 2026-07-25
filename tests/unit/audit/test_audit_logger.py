from datetime import UTC, datetime

from aegis.audit.logger import AuditLogger
from aegis.audit.repository import InMemoryAuditRepository
from aegis.common.clock import FakeClock
from aegis.common.metrics import create_metrics


def test_record_persists_all_fields():
    repo = InMemoryAuditRepository()
    logger = AuditLogger(repo, FakeClock(), create_metrics())

    logger.record(
        principal_id="user-1",
        action="kv.write",
        resource_type="secret",
        resource_id="db/password",
        outcome="success",
        metadata={"foo": "bar"},
    )

    assert len(repo.events) == 1
    event = repo.events[0]
    assert event.principal_id == "user-1"
    assert event.action == "kv.write"
    assert event.resource_type == "secret"
    assert event.resource_id == "db/password"
    assert event.outcome == "success"
    assert event.metadata == {"foo": "bar"}


def test_record_defaults_metadata_to_empty_dict_not_none():
    repo = InMemoryAuditRepository()
    logger = AuditLogger(repo, FakeClock(), create_metrics())

    logger.record(
        principal_id="user-1",
        action="kv.read",
        resource_type="secret",
        resource_id="x",
        outcome="success",
        metadata=None,
    )

    assert repo.events[0].metadata == {}


def test_each_record_call_gets_a_unique_id():
    repo = InMemoryAuditRepository()
    logger = AuditLogger(repo, FakeClock(), create_metrics())

    logger.record("u", "kv.read", "secret", "a", "success")
    logger.record("u", "kv.read", "secret", "b", "success")

    assert repo.events[0].id != repo.events[1].id


def test_timestamp_comes_from_the_injected_clock_not_wall_time():
    fixed_time = datetime(2030, 1, 1, tzinfo=UTC)
    clock = FakeClock(start=fixed_time)
    repo = InMemoryAuditRepository()
    logger = AuditLogger(repo, clock, create_metrics())

    logger.record("u", "kv.read", "secret", "a", "success")

    assert repo.events[0].timestamp == fixed_time


def test_kv_action_increments_kv_operations_metric():
    metrics = create_metrics()
    logger = AuditLogger(InMemoryAuditRepository(), FakeClock(), metrics)

    logger.record("u", "kv.write", "secret", "a", "success")

    value = metrics.kv_operations_total.labels(action="write", outcome="success")._value.get()
    assert value == 1


def test_transit_action_increments_transit_operations_metric():
    metrics = create_metrics()
    logger = AuditLogger(InMemoryAuditRepository(), FakeClock(), metrics)

    logger.record("u", "transit.sign", "transit_key", "a", "success")

    value = metrics.transit_operations_total.labels(action="sign", outcome="success")._value.get()
    assert value == 1


def test_two_different_apps_metrics_do_not_share_state():
    metrics_a = create_metrics()
    metrics_b = create_metrics()

    AuditLogger(InMemoryAuditRepository(), FakeClock(), metrics_a).record(
        "u", "kv.write", "secret", "a", "success"
    )

    value_a = metrics_a.kv_operations_total.labels(action="write", outcome="success")._value.get()
    value_b = metrics_b.kv_operations_total.labels(action="write", outcome="success")._value.get()

    assert value_a == 1
    assert value_b == 0
