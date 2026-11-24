"""Every role against every tenant endpoint, plus callers that must never reach a tenant.

For members of the organization the request-level answer is 403 exactly when the caller lacks the
endpoint's permission. Callers without an active membership in an active organization get the
same 404 everywhere (401 for an inactive account), whatever their platform status.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest

from apps.accounts.models import User
from apps.audit.models import AuditLog
from apps.organizations.models import Organization, OrganizationStatus
from apps.organizations.tests.conftest import Api, bearer

from .conftest import Team, member, url

pytestmark = pytest.mark.django_db


@dataclass(frozen=True)
class Endpoint:
    name: str
    method: str
    path: Callable[[Team, Any], str]
    permission: str | None  # None: any active member (read-only member action)
    body: Callable[[Team], Any] | None = None


def _victim(team: Team) -> Any:
    return member(team.org, User.objects.create_user("victim@example.org", "x" * 12, full_name="V"))


ENDPOINTS = [
    Endpoint("org-detail", "get", lambda t, v: url(t.org), "organization.view"),  # AEMS-017
    Endpoint(
        "org-update",
        "patch",
        lambda t, v: url(t.org),
        "organization.update",
        lambda t: {"name": "N"},
    ),
    Endpoint("me", "get", lambda t, v: url(t.org, "me/"), None),
    Endpoint("audit-logs", "get", lambda t, v: url(t.org, "audit-logs/"), "audit.view"),
    Endpoint("members-list", "get", lambda t, v: url(t.org, "members/"), "members.view"),
    Endpoint("member-detail", "get", lambda t, v: url(t.org, f"members/{v.pk}/"), "members.view"),
    Endpoint(
        "member-update",
        "patch",
        lambda t, v: url(t.org, f"members/{v.pk}/"),
        "members.manage",
        lambda t: {"status": "suspended"},
    ),
    Endpoint(
        "member-remove", "delete", lambda t, v: url(t.org, f"members/{v.pk}/"), "members.manage"
    ),
    Endpoint(
        "member-roles",
        "put",
        lambda t, v: url(t.org, f"members/{v.pk}/roles/"),
        "members.manage",
        lambda t: {"role_ids": []},
    ),
    Endpoint("roles-list", "get", lambda t, v: url(t.org, "roles/"), "roles.view"),
    Endpoint(
        "role-create",
        "post",
        lambda t, v: url(t.org, "roles/"),
        "roles.manage",
        lambda t: {"name": "Fresh", "permissions": []},
    ),
    Endpoint(
        "role-detail", "get", lambda t, v: url(t.org, f"roles/{t.auditors.pk}/"), "roles.view"
    ),
    Endpoint(
        "role-update",
        "patch",
        lambda t, v: url(t.org, f"roles/{t.auditors.pk}/"),
        "roles.manage",
        lambda t: {"description": "Updated"},
    ),
    Endpoint(
        "role-delete", "delete", lambda t, v: url(t.org, f"roles/{t.auditors.pk}/"), "roles.manage"
    ),
    Endpoint("permissions", "get", lambda t, v: url(t.org, "permissions/"), "roles.view"),
]
ROLE_HOLDERS = {
    "owner": None,  # all permissions
    "admin": None,  # Admin default: all Phase 1 permissions
    "member": {"organization.view"},
    "auditor": {"audit.view"},
    "norole": set(),
}


def _call(client: Api, endpoint: Endpoint, team: Team, victim: Any) -> Any:
    path = endpoint.path(team, victim)
    method = getattr(client, endpoint.method)
    if endpoint.body is not None:
        return method(path, endpoint.body(team))
    return method(path)


@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=[e.name for e in ENDPOINTS])
@pytest.mark.parametrize("caller", list(ROLE_HOLDERS))
def test_role_by_endpoint(
    team: Team, as_user: Callable[..., Api], caller: str, endpoint: Endpoint
) -> None:
    victim = _victim(team)
    held = ROLE_HOLDERS[caller]
    allowed = endpoint.permission is None or held is None or endpoint.permission in held
    response = _call(as_user(getattr(team, caller)), endpoint, team, victim)
    if allowed:
        assert response.status_code not in {401, 403, 404}, response.content
    else:
        assert response.status_code == 403, response.content
        assert response.json()["code"] == "permission_denied"


NON_MEMBERS = ["suspended", "other_owner", "outsider", "platform_admin", "superuser"]


@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=[e.name for e in ENDPOINTS])
@pytest.mark.parametrize("caller", NON_MEMBERS)
def test_callers_without_an_active_membership_get_404(
    team: Team, as_user: Callable[..., Api], caller: str, endpoint: Endpoint
) -> None:
    victim = _victim(team)
    response = _call(as_user(getattr(team, caller)), endpoint, team, victim)
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"


@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=[e.name for e in ENDPOINTS])
def test_inactive_accounts_and_anonymous_callers_get_401(
    team: Team, as_user: Callable[..., Api], endpoint: Endpoint
) -> None:
    victim = _victim(team)
    for client in (Api(bearer(team.inactive)), as_user(None)):
        assert _call(client, endpoint, team, victim).status_code == 401


@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=[e.name for e in ENDPOINTS])
@pytest.mark.parametrize("status", [OrganizationStatus.SUSPENDED, OrganizationStatus.PROVISIONING])
def test_inactive_organizations_are_closed_even_to_owners(
    team: Team, as_user: Callable[..., Api], endpoint: Endpoint, status: str
) -> None:
    victim = _victim(team)
    client = as_user(team.owner)
    Organization.objects.filter(pk=team.org.pk).update(status=status)
    assert _call(client, endpoint, team, victim).status_code == 404


@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=[e.name for e in ENDPOINTS])
def test_roles_in_one_organization_grant_nothing_in_another(
    team: Team, as_user: Callable[..., Api], endpoint: Endpoint
) -> None:
    """The Admin of A is an ordinary Member of B: B answers as for a Member."""
    victim = member(team.other, User.objects.create_user("vb@example.org", "x" * 12, full_name="V"))
    path = endpoint.path(team, victim).replace(str(team.org.pk), str(team.other.pk))
    client = as_user(team.admin)
    method = getattr(client, endpoint.method)
    response = method(path, endpoint.body(team)) if endpoint.body else method(path)
    if endpoint.permission in (None, "organization.view"):
        assert response.status_code == 200
    else:
        assert response.status_code == 403


AUDIT_CASES = {
    "owner": 200,
    "admin": 200,
    "auditor": 200,  # custom role holding audit.view
    "member": 403,
    "norole": 403,
    "suspended": 404,
    "other_owner": 404,  # cross-tenant
    "platform_admin": 404,
    "superuser": 404,
}


@pytest.mark.parametrize(("caller", "expected"), AUDIT_CASES.items())
def test_audit_history_access(
    team: Team, as_user: Callable[..., Api], caller: str, expected: int
) -> None:
    AuditLog.objects.create(action="organization.updated", outcome="success", organization=team.org)
    AuditLog.objects.create(
        action="organization.updated", outcome="success", organization=team.other
    )
    response = as_user(getattr(team, caller)).get(url(team.org, "audit-logs/"))
    assert response.status_code == expected
    if expected == 200:
        results = response.json()["results"]
        assert results
        assert {r["organization"] for r in results} == {str(team.org.pk)}


def test_admin_without_audit_view(team: Team, as_user: Callable[..., Api]) -> None:
    from .conftest import role  # noqa: PLC0415

    role(team.org, "admin").permissions.remove(
        *role(team.org, "admin").permissions.filter(code="audit.view")
    )
    assert as_user(team.admin).get(url(team.org, "audit-logs/")).status_code == 403
    # The platform endpoint keeps its separate model-permission policy.
    assert as_user(team.admin).get("/api/v1/platform/audit-logs/").status_code == 403
    assert as_user(team.owner).get("/api/v1/platform/audit-logs/").status_code == 403
