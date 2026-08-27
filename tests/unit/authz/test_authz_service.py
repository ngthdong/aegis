from __future__ import annotations

from dataclasses import dataclass

import pytest

from aegis.auth.session_service import Principal
from aegis.authz.service import AuthzService, PermissionDenied


@dataclass(frozen=True, slots=True)
class StubResource:
    id: str
    owner_id: str


ALICE = Principal(user_id="user-alice", username="alice")
BOB = Principal(user_id="user-bob", username="bob")
ADMIN = Principal(user_id="user-admin", username="root", role="admin")


@pytest.fixture
def authz() -> AuthzService:
    return AuthzService()


def test_owner_can_access_own_resource(authz: AuthzService):
    resource = StubResource(id="r1", owner_id=ALICE.user_id)
    assert authz.can(ALICE, "read", resource) is True


def test_non_owner_cannot_access_resource(authz: AuthzService):
    resource = StubResource(id="r1", owner_id=ALICE.user_id)
    assert authz.can(BOB, "read", resource) is False


def test_require_raises_for_non_owner(authz: AuthzService):
    resource = StubResource(id="r1", owner_id=ALICE.user_id)
    with pytest.raises(PermissionDenied):
        authz.require(BOB, "read", resource)


def test_require_does_not_raise_for_owner(authz: AuthzService):
    resource = StubResource(id="r1", owner_id=ALICE.user_id)
    authz.require(ALICE, "read", resource)  # must not raise


def test_action_name_does_not_affect_ownership_check(authz: AuthzService):
    resource = StubResource(id="r1", owner_id=ALICE.user_id)
    assert authz.can(ALICE, "read", resource) == authz.can(ALICE, "delete", resource) is True
    assert authz.can(BOB, "read", resource) == authz.can(BOB, "delete", resource) is False


def test_permission_denied_message_does_not_leak_resource_content(authz: AuthzService):
    resource = StubResource(id="r1", owner_id=ALICE.user_id)
    with pytest.raises(PermissionDenied) as exc_info:
        authz.require(BOB, "read", resource)
    assert resource.owner_id not in str(exc_info.value)
    assert resource.id not in str(exc_info.value)


def test_is_admin_true_for_admin_role(authz: AuthzService):
    assert authz.is_admin(ADMIN) is True


def test_is_admin_false_for_regular_user(authz: AuthzService):
    assert authz.is_admin(ALICE) is False


def test_require_admin_does_not_raise_for_admin(authz: AuthzService):
    authz.require_admin(ADMIN)  # must not raise


def test_require_admin_raises_for_regular_user(authz: AuthzService):
    with pytest.raises(PermissionDenied):
        authz.require_admin(ALICE)
