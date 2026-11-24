"""Fixtures for organization and tenant-isolation tests.

**Test-only activation.** Production code has no way to make an organization ``active``: that
happens when the initial Owner accepts their invitation (Batch 7). Tests that need an active
organization use :func:`activate_for_tests`, which writes the status directly with a queryset
update. It lives only in this test package and must never be
imported by application code (asserted by ``test_activation_helper_is_test_only``).
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest
from django.contrib.auth.models import Permission
from django.test import Client

from apps.accounts.models import User
from apps.accounts.sessions import create_session
from apps.accounts.tests.conftest import PASSWORD
from apps.organizations.models import (
    Membership,
    MembershipStatus,
    Organization,
    OrganizationStatus,
    OrganizationType,
)
from apps.rbac.models import MembershipRole, Role, SystemRole
from apps.rbac.services import seed_system_roles


def activate_for_tests(organization: Organization) -> Organization:
    """TEST ONLY: mark an organization active without the Owner lifecycle (see module docs)."""
    Organization.objects.filter(pk=organization.pk).update(status=OrganizationStatus.ACTIVE)
    organization.refresh_from_db()
    return organization


def error_fields(response: Any) -> set[str]:
    """Field names of a Problem Details validation response (``errors[].pointer``)."""
    return {e.get("pointer", "").removeprefix("#/") for e in response.json().get("errors", [])}


def bearer(user: User) -> dict[str, Any]:
    tokens = create_session(user, client_ip=None)
    return {"HTTP_AUTHORIZATION": f"Bearer {tokens.access_token}"}


@dataclass
class Api:
    """A JSON client authenticated as one user (or anonymous)."""

    headers: dict[str, Any]

    def get(self, path: str, **extra: Any) -> Any:
        return Client().get(path, **self.headers, **extra)

    def post(self, path: str, data: Any = None) -> Any:
        return Client().post(path, data or {}, content_type="application/json", **self.headers)

    def patch(self, path: str, data: Any = None) -> Any:
        return Client().patch(path, data or {}, content_type="application/json", **self.headers)

    def put(self, path: str, data: Any = None) -> Any:
        return Client().put(path, data or {}, content_type="application/json", **self.headers)

    def delete(self, path: str) -> Any:
        return Client().delete(path, **self.headers)


@pytest.fixture
def make_user(db: Any) -> Callable[..., User]:
    counter = {"n": 0}

    def _make(email: str | None = None, **extra: Any) -> User:
        counter["n"] += 1
        extra.setdefault("full_name", f"User {counter['n']}")
        return User.objects.create_user(
            email or f"user{counter['n']}@example.org", PASSWORD, **extra
        )

    return _make


@pytest.fixture
def platform_admin(make_user: Callable[..., User]) -> User:
    """Staff with the organization model permissions and **no** tenant membership."""
    user = make_user("platform@example.org", is_staff=True)
    user.user_permissions.add(
        *Permission.objects.filter(
            content_type__app_label="organizations",
            codename__in=[
                "view_organization",
                "add_organization",
                "change_organization",
                "manage_initial_owner_invitation",
            ],
        )
    )
    return User.objects.get(pk=user.pk)  # reload: permission cache


@pytest.fixture
def make_org(platform_admin: User) -> Callable[..., Organization]:
    counter = {"n": 0}

    def _make(status: str = OrganizationStatus.ACTIVE, **extra: Any) -> Organization:
        counter["n"] += 1
        extra.setdefault("name", f"Organization {counter['n']}")
        extra.setdefault("slug", f"org-{counter['n']}")
        extra.setdefault("organization_type", OrganizationType.SCHOOL)
        organization = Organization.objects.create(created_by=platform_admin, **extra)
        seed_system_roles(organization)  # as create_organization() does
        if status == OrganizationStatus.ACTIVE:
            activate_for_tests(organization)
        elif status != OrganizationStatus.PROVISIONING:
            Organization.objects.filter(pk=organization.pk).update(status=status)
            organization.refresh_from_db()
        return organization

    return _make


def add_member(
    organization: Organization, user: User, status: str = MembershipStatus.ACTIVE
) -> Membership:
    return Membership.objects.create(organization=organization, user=user, status=status)


def add_default_member(
    organization: Organization, user: User, status: str = MembershipStatus.ACTIVE
) -> Membership:
    """TEST ONLY: a membership holding the default Member role (as real members do)."""
    membership = add_member(organization, user, status)
    MembershipRole(
        organization=organization,
        membership=membership,
        role=Role.objects.get(organization=organization, system_key=SystemRole.MEMBER),
    ).save()
    return membership


@dataclass
class World:
    """Two organizations plus every kind of caller the isolation matrix needs."""

    org_a: Organization
    org_b: Organization
    provisioning: Organization
    suspended: Organization
    alice: User  # member of A only
    bob: User  # member of B only
    carol: User  # member of A and B
    dave: User  # suspended membership in A
    erin: User  # member of the provisioning and suspended organizations
    platform_admin: User  # staff, all organization model permissions, no memberships
    outsider: User  # no memberships at all


@pytest.fixture
def world(
    make_user: Callable[..., User], make_org: Callable[..., Organization], platform_admin: User
) -> World:
    org_a, org_b = make_org(slug="alpha"), make_org(slug="beta")
    provisioning = make_org(OrganizationStatus.PROVISIONING, slug="pending")
    suspended = make_org(OrganizationStatus.SUSPENDED, slug="paused")
    w = World(
        org_a=org_a,
        org_b=org_b,
        provisioning=provisioning,
        suspended=suspended,
        alice=make_user("alice@example.org"),
        bob=make_user("bob@example.org"),
        carol=make_user("carol@example.org"),
        dave=make_user("dave@example.org"),
        erin=make_user("erin@example.org"),
        platform_admin=platform_admin,
        outsider=make_user("outsider@example.org"),
    )
    add_default_member(org_a, w.alice)
    add_default_member(org_b, w.bob)
    add_default_member(org_a, w.carol)
    add_default_member(org_b, w.carol)
    add_default_member(org_a, w.dave, MembershipStatus.SUSPENDED)
    add_default_member(provisioning, w.erin)
    add_default_member(suspended, w.erin)
    return w


@pytest.fixture
def api() -> Callable[[User | None], Api]:
    def _api(user: User | None) -> Api:
        return Api(bearer(user) if user is not None else {})

    return _api


@pytest.fixture
def team(
    make_user: Callable[..., User], make_org: Callable[..., Organization], platform_admin: User
) -> Any:
    """The RBAC test organization (one member per kind of role), for invitation tests."""
    from apps.rbac.tests.conftest import build_team  # noqa: PLC0415 - avoids an import cycle

    return build_team(make_user, make_org, platform_admin)


@pytest.fixture
def as_user(api: Callable[[User | None], Api]) -> Callable[[User | None], Api]:
    return api
