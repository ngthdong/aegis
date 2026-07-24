from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

AuditOutcome = Literal["success", "denied", "error"]


@dataclass(frozen=True, slots=True)
class AuditEvent:
    id: str
    timestamp: datetime
    principal_id: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    outcome: AuditOutcome
    metadata: dict[str, Any] = field(default_factory=dict)
