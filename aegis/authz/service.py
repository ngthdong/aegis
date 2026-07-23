from __future__ import annotations

from typing import Protocol

from aegis.auth.session_service import Principal
from aegis.common.logging import get_logger

logger = get_logger(__name__)


class OwnedResource(Protocol):
    owner_id: str


class PermissionDenied(Exception):
    pass


class AuthzService:
    def can(self, principal: Principal, action: str, resource: OwnedResource) -> bool:
        return resource.owner_id == principal.user_id

    def require(self, principal: Principal, action: str, resource: OwnedResource) -> None:
        if not self.can(principal, action, resource):
            logger.warning(
                "authz.denied",
                principal_id=principal.user_id,
                action=action,
                resource_owner_id=resource.owner_id,
            )
            raise PermissionDenied(f"principal is not authorized to {action} this resource")
