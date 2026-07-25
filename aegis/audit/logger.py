from __future__ import annotations

import uuid
from typing import Any

from aegis.audit.models import AuditEvent, AuditOutcome
from aegis.audit.repository import AuditRepository
from aegis.common.clock import Clock
from aegis.common.logging import get_logger
from aegis.common.metrics import Metrics

logger = get_logger(__name__)


class AuditLogger:
    def __init__(self, repository: AuditRepository, clock: Clock, metrics: Metrics) -> None:
        self._repository = repository
        self._clock = clock
        self._metrics = metrics

    def record(
        self,
        principal_id: str | None,
        action: str,
        resource_type: str | None,
        resource_id: str | None,
        outcome: AuditOutcome,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        event = AuditEvent(
            id=uuid.uuid4().hex,
            timestamp=self._clock.now(),
            principal_id=principal_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            metadata=metadata or {},
        )
        self._repository.save(event)
        self._increment_metric(action, outcome)

        log_fn = logger.info if outcome == "success" else logger.warning
        log_fn(
            "audit.event",
            action=action,
            outcome=outcome,
            principal_id=principal_id,
            resource_type=resource_type,
            resource_id=resource_id,
        )

    def _increment_metric(self, action: str, outcome: AuditOutcome) -> None:
        if action.startswith("kv."):
            self._metrics.kv_operations_total.labels(
                action=action.removeprefix("kv."), outcome=outcome
            ).inc()
        elif action.startswith("transit."):
            self._metrics.transit_operations_total.labels(
                action=action.removeprefix("transit."), outcome=outcome
            ).inc()
