"""Permission evaluation: union of roles, Owner coverage, state checks, caching, query count."""

from typing import Any

import pytest
from django.contrib.auth.models import Permission as DjangoPermission
from django.db import connection
from django.test.utils import CaptureQueriesContext

from apps.accounts.models import User
from apps.organizations.models import (
    Membership,
    MembershipStatus,
    Organization,
    OrganizationStatus,
)
from apps.organizations.permissions import HasOrgPermission, membership_has_permissions
from apps.rbac import engine
from apps.rbac.models import Permission
from apps.rbac.registry import registry

from .conftest import Team, custom_role, grant, role
from .test_registry_and_models import PHASE_1_CATALOG

pytestmark = pytest.mark.django_db


def permissions_of(team: Team, user: User, organization: Organization | None = None) -> set[str]:
    return set(engine.fresh_permissions(team.membership(user, organization).pk)[0])


def test_effective_permissions_per_role(team: Team) -> None:
    assert permissions_of(team, team.owner) == PHASE_1_CATALOG
    assert permissions_of(team, team.admin) == PHASE_1_CATALOG  # Admin default set
    assert permissions_of(team, team.member) == {"organization.view"}
    assert permissions_of(team, team.auditor) == {"audit.view"}
    assert permissions_of(team, team.norole) == set()


def test_permissions_are_the_union_of_all_roles(team: Team) -> None:
    membership = team.membership(team.member)
    grant(membership, custom_role(team.org, "Viewers", "members.view", "roles.view"))
    assert permissions_of(team, team.member) == {"organization.view", "members.view", "roles.view"}


def test_roles_never_cross_organizations(team: Team) -> None:
    # Admin in A, ordinary member in B.
    assert permissions_of(team, team.admin, team.other) == {"organization.view"}
    assert permissions_of(team, team.other_owner, team.other) == PHASE_1_CATALOG


@pytest.mark.parametrize("state", ["inactive_user", "suspended_membership", "inactive_org"])
def test_inactive_state_holds_nothing(team: Team, state: str) -> None:
    membership = team.membership(team.owner)
    if state == "inactive_user":
        User.objects.filter(pk=team.owner.pk).update(is_active=False)
    elif state == "suspended_membership":
        Membership.objects.filter(pk=membership.pk).update(status=MembershipStatus.SUSPENDED)
    else:
        Organization.objects.filter(pk=team.org.pk).update(status=OrganizationStatus.SUSPENDED)
    assert engine.fresh_permissions(membership.pk) == (frozenset(), False)


def test_unknown_and_deprecated_codes_grant_nothing(team: Team) -> None:
    membership = team.membership(team.member)
    stale = Permission.objects.create(code="legacy.manage", description="Old.", category="legacy")
    role(team.org, "member").permissions.add(stale)
    Permission.objects.filter(code="organization.view").update(is_deprecated=True)
    assert permissions_of(team, team.member) == set()
    assert not engine.has_permissions(membership, ["legacy.manage"])
    assert not engine.has_permissions(membership, ["organization.view"])  # deprecated in DB


def test_has_permissions_defaults_to_deny(team: Team) -> None:
    owner = team.membership(team.owner)
    assert engine.has_permissions(owner, ["audit.view", "roles.manage"])
    assert not engine.has_permissions(owner, [])  # nothing declared: deny
    assert not engine.has_permissions(owner, ["audit.view", "nonexistent.permission"])
    assert membership_has_permissions(owner, ["members.manage"])


def test_django_model_permissions_and_staff_status_are_not_tenant_permissions(
    team: Team,
) -> None:
    User.objects.filter(pk=team.norole.pk).update(is_staff=True, is_superuser=True)
    team.norole.user_permissions.add(*DjangoPermission.objects.all())
    assert permissions_of(team, team.norole) == set()


def test_one_query_and_per_instance_cache(team: Team) -> None:
    membership = team.membership(team.admin)
    with CaptureQueriesContext(connection) as queries:
        first = engine.effective_permissions(membership)
        second = engine.effective_permissions(membership)
    assert first == second == PHASE_1_CATALOG
    assert len(queries) == 1
    # A new instance (a new request) never sees a stale cache.
    role(team.org, "admin").permissions.clear()
    assert engine.effective_permissions(team.membership(team.admin)) == frozenset()
    assert engine.effective_permissions(membership) == PHASE_1_CATALOG  # same request: cached


def test_owner_coverage_follows_the_registry(team: Team) -> None:
    registry.register("reports.view", "View reports.", category="reports")
    try:
        assert "reports.view" in permissions_of(team, team.owner)
        assert "reports.view" not in permissions_of(team, team.admin)
    finally:
        registry._definitions.pop("reports.view")


class _View:
    def __init__(self, **attrs: Any) -> None:
        self.__dict__.update(attrs)


class _Request:
    def __init__(self, method: str, membership: Any) -> None:
        self.method = method
        self.membership = membership


def test_has_org_permission_uses_the_engine_with_default_deny(team: Team) -> None:
    check = HasOrgPermission().has_permission
    auditor = team.membership(team.auditor)
    view = _View(required_permissions={"get": ("audit.view",), "post": ("roles.manage",)})
    assert check(_Request("GET", auditor), view)  # type: ignore[arg-type]
    assert not check(_Request("POST", auditor), view)  # type: ignore[arg-type]
    assert not check(_Request("DELETE", auditor), view)  # type: ignore[arg-type]  # undeclared
    assert not check(_Request("GET", None), view)  # type: ignore[arg-type]
    unknown = _View(required_permissions={"get": ("audit.export",)})
    assert not check(_Request("GET", team.membership(team.owner)), unknown)  # type: ignore[arg-type]
