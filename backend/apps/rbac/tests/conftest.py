"""RBAC fixtures.

**Test-only role assignment.** :func:`grant` writes ``MembershipRole`` rows directly, like
``activate_for_tests`` writes organization status: production code assigns roles only through
``rbac.services`` (and, from Batch 7, the initial Owner invitation). It must never be imported by
application code.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest

from apps.accounts.models import User
from apps.accounts.tests.conftest import events  # noqa: F401 - re-exported fixture
from apps.audit.models import AuditLog
from apps.organizations.models import Membership, MembershipStatus, Organization
from apps.organizations.tests.conftest import (  # noqa: F401 - re-exported fixtures
    Api,
    add_member,
    api,
    make_org,
    make_user,
    platform_admin,
)
from apps.rbac.models import MembershipRole, Permission, Role, SystemRole


def role(organization: Organization, key: str) -> Role:
    found: Role = Role.objects.for_organization(organization).get(system_key=key)
    return found


def grant(membership: Membership, *roles: Role) -> Membership:
    """TEST ONLY: assign roles without the service rules (see module docs)."""
    for r in roles:
        MembershipRole(
            organization_id=membership.organization_id, membership=membership, role=r
        ).save()
    return membership


def custom_role(organization: Organization, name: str, *codes: str) -> Role:
    r = Role(organization=organization, name=name)
    r.save()
    r.permissions.set(Permission.objects.filter(code__in=codes))
    return r


def member(
    organization: Organization,
    user: User,
    *roles: Role,
    status: str = MembershipStatus.ACTIVE,
) -> Membership:
    return grant(add_member(organization, user, status), *roles)


def audit_rows(action: str, **filters: Any) -> list[AuditLog]:
    return list(AuditLog.objects.filter(action=action, **filters).order_by("created_at", "id"))


@dataclass
class Team:
    """Organization A with one member per kind of role, organization B, and outsiders."""

    org: Organization
    other: Organization
    owner: User
    admin: User
    member: User
    auditor: User  # custom role "Auditors" with audit.view only
    norole: User  # active member without roles
    suspended: User  # suspended membership holding Admin
    inactive: User  # inactive account holding Admin
    other_owner: User  # Owner of B only
    outsider: User
    platform_admin: User
    superuser: User
    auditors: Role

    def membership(self, user: User, organization: Organization | None = None) -> Membership:
        return Membership.objects.get(organization=organization or self.org, user=user)


@pytest.fixture
def team(
    make_user: Callable[..., User],  # noqa: F811
    make_org: Callable[..., Organization],  # noqa: F811
    platform_admin: User,  # noqa: F811
) -> Team:
    org, other = make_org(slug="acme"), make_org(slug="globex")
    users = {
        name: make_user(f"{name}@example.org")
        for name in (
            "owner",
            "admin",
            "member",
            "auditor",
            "norole",
            "suspended",
            "inactive",
            "other_owner",
            "outsider",
        )
    }
    auditors = custom_role(org, "Auditors", "audit.view")
    member(org, users["owner"], role(org, SystemRole.OWNER))
    member(org, users["admin"], role(org, SystemRole.ADMIN))
    member(org, users["member"], role(org, SystemRole.MEMBER))
    member(org, users["auditor"], auditors)
    member(org, users["norole"])
    member(org, users["suspended"], role(org, SystemRole.ADMIN), status=MembershipStatus.SUSPENDED)
    member(org, users["inactive"], role(org, SystemRole.ADMIN))
    User.objects.filter(pk=users["inactive"].pk).update(is_active=False)
    member(other, users["other_owner"], role(other, SystemRole.OWNER))
    # The admin of A is an ordinary member in B: roles never cross organizations.
    member(other, users["admin"], role(other, SystemRole.MEMBER))
    superuser = User.objects.create_superuser(
        "root@example.org", "Correct-Horse-Battery-42", full_name="Root"
    )
    return Team(
        org=org,
        other=other,
        owner=users["owner"],
        admin=users["admin"],
        member=users["member"],
        auditor=users["auditor"],
        norole=users["norole"],
        suspended=users["suspended"],
        inactive=User.objects.get(pk=users["inactive"].pk),
        other_owner=users["other_owner"],
        outsider=users["outsider"],
        platform_admin=platform_admin,
        superuser=superuser,
        auditors=auditors,
    )


def url(organization: Organization, path: str = "") -> str:
    return f"/api/v1/organizations/{organization.pk}/{path}"


@pytest.fixture
def as_user(api: Callable[[User | None], Api]) -> Callable[[User | None], Api]:  # noqa: F811
    return api
