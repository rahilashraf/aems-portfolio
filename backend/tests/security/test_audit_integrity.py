"""Audit-log integrity (plan §7, ADR-0006, ADR-0016, ADR-0019).

Append-only enforcement and runtime privileges are attacked with raw SQL in
``test_database_safeguards.py``; tenant scoping of audit queries in the isolation matrix. This
suite covers completeness, failure atomicity, injection and redaction.
"""

import re
from collections.abc import Callable
from typing import Any

import pytest
from django.test import Client

from apps.accounts.models import User
from apps.accounts.tests.conftest import PASSWORD, do_login
from apps.audit import services as audit_services
from apps.audit.models import AuditLog
from apps.organizations.models import Invitation, Membership, Organization
from apps.organizations.tests.conftest import Api, bearer
from apps.rbac.models import Role
from apps.rbac.tests.conftest import Team, role, url


def _headers(session: Any) -> dict[str, Any]:
    return dict(session.auth)


pytestmark = pytest.mark.django_db
JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")


def _mutations(team: Team) -> list[tuple[str, Callable[[Api], Any], str]]:
    member_id = team.membership(team.member).pk
    return [
        (
            "organization",
            lambda c: c.patch(url(team.org), {"name": "Renamed Org"}),
            "organization.profile_updated",
        ),
        (
            "role-create",
            lambda c: c.post(
                url(team.org, "roles/"), {"name": "Graders", "permissions": ["members.view"]}
            ),
            "rbac.role.created",
        ),
        (
            "member-suspend",
            lambda c: c.patch(url(team.org, f"members/{member_id}/"), {"status": "suspended"}),
            "rbac.membership.status_changed",
        ),
        (
            "member-roles",
            lambda c: c.put(
                url(team.org, f"members/{member_id}/roles/"), {"role_ids": [str(team.auditors.pk)]}
            ),
            "rbac.membership.roles_replaced",
        ),
        (
            "invite",
            lambda c: c.post(
                url(team.org, "invitations/"),
                {"email": "audited@example.org", "role_ids": [str(role(team.org, "member").pk)]},
            ),
            "invitation.created",
        ),
    ]


def _state() -> Any:
    return (
        sorted(Organization.objects.values_list("id", "name")),
        sorted(Role.objects.values_list("id", "name")),
        sorted(Membership.objects.values_list("id", "status")),
        Invitation.objects.count(),
        sorted(str(r) for r in Role.objects.values_list("id", "permissions")),
    )


@pytest.mark.parametrize("index", range(5))
def test_successful_mutations_record_their_event_with_actor_and_tenant(
    team: Team, index: int
) -> None:
    name, call, action = _mutations(team)[index]
    response = call(Api(bearer(team.owner)))
    assert response.status_code in (200, 201), (name, response.content)
    entry = AuditLog.objects.filter(action=action).latest("created_at")
    assert entry.outcome == "success"
    assert entry.actor_id == team.owner.pk
    assert entry.organization_id == team.org.pk
    assert entry.request_id


@pytest.mark.parametrize("index", range(5))
def test_audit_failure_rolls_back_the_mutation(
    team: Team, index: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    name, call, action = _mutations(team)[index]
    before, count = _state(), AuditLog.objects.count()
    real_insert = audit_services._insert

    def failing_insert(event: str, **kwargs: Any) -> Any:
        if event == action:
            msg = "audit storage unavailable"
            raise RuntimeError(msg)
        return real_insert(event, **kwargs)

    monkeypatch.setattr(audit_services, "_insert", failing_insert)
    client = Api(bearer(team.owner))
    from django.test import Client as DjangoClient  # noqa: PLC0415

    monkeypatch.setattr(
        "apps.organizations.tests.conftest.Client",
        lambda: DjangoClient(raise_request_exception=False),
    )
    response = call(client)
    assert response.status_code == 500, (name, response.content)
    assert _state() == before
    assert AuditLog.objects.count() == count


def test_refused_mutations_record_no_success(team: Team) -> None:
    client = Api(bearer(team.owner))
    owner_membership = team.membership(team.owner)
    response = client.patch(
        url(team.org, f"members/{owner_membership.pk}/"), {"status": "suspended"}
    )
    assert response.status_code == 403  # self-modification
    response = Api(bearer(team.member)).post(
        url(team.org, "roles/"), {"name": "X", "permissions": []}
    )
    assert response.status_code == 403
    assert not AuditLog.objects.filter(outcome="success", action__startswith="rbac.").exists()


def test_request_bodies_never_reach_audit_rows(team: Team) -> None:
    marker = "INJECTED-MARKER-7f3a"
    client = Api(bearer(team.owner))
    client.patch(url(team.org), {"name": "Renamed", "metadata": {"x": marker}, "note": marker})
    client.post(
        url(team.org, "roles/"), {"name": f"R {marker}", "permissions": [], "extra": marker}
    )
    client.patch(url(team.org), {"name": "Again"})
    text = repr(list(AuditLog.objects.values("metadata", "changes", "action", "target_type")))
    # Only allowlisted change fields are recorded; the role name is a recorded value, unknown
    # keys and nested objects never are.
    assert "'note'" not in text
    assert "'extra'" not in text
    assert "metadata': {'x'" not in text


def test_secret_scan_over_every_recorded_event(team: Team, make_user: Any) -> None:
    """Exercise authentication and tenant flows, then scan every audit row for secrets."""
    user = make_user("scan@example.org")
    session = do_login(user.email)
    session.refresh()
    Client().post(
        "/api/v1/auth/login/",
        {"email": user.email, "password": "Wrong-Password-1!"},
        content_type="application/json",
    )
    Client().post(
        "/api/v1/auth/password/change/",
        {"current_password": PASSWORD, "new_password": "Scanned-New-Passphrase-33"},
        content_type="application/json",
        **_headers(session),
    )
    Api(bearer(team.owner)).post(
        url(team.org, "invitations/"),
        {"email": "scan-invite@example.org", "role_ids": [str(role(team.org, "member").pk)]},
    )
    rows = repr(list(AuditLog.objects.values()))
    fresh = User.objects.get(pk=user.pk)
    for secret in (
        PASSWORD,
        "Wrong-Password-1!",
        "Scanned-New-Passphrase-33",
        fresh.password,
        session.access_token,
        session.refresh_token,
    ):
        assert secret not in rows
    assert not JWT.search(rows)
    assert "argon2" not in rows
    # The only 64-hex values allowed are HMAC subject digests (keyed, never reversible).
    digests = {d for d in AuditLog.objects.values_list("metadata__subject_digest", flat=True) if d}
    assert set(re.findall(r"[0-9a-f]{64}", rows)) <= digests


def test_tenant_audit_filters_never_reach_other_tenants(team: Team) -> None:
    AuditLog.objects.create(
        action="organization.updated",
        outcome="success",
        organization=team.other,
        actor=team.other_owner,
    )
    AuditLog.objects.create(
        action="auth.login.succeeded", outcome="success", actor=team.owner
    )  # platform-level
    client = Api(bearer(team.owner))
    for query in (
        f"actor={team.other_owner.pk}",
        "action=organization.updated",
        "action=auth.login.succeeded",
        "page_size=100",
        "outcome=success",
    ):
        response = client.get(url(team.org, f"audit-logs/?{query}"))
        assert response.status_code == 200
        assert {r["organization"] for r in response.json()["results"]} <= {str(team.org.pk)}


def test_platform_audit_requires_the_explicit_model_permission(team: Team) -> None:
    from django.contrib.auth.models import Permission  # noqa: PLC0415

    AuditLog.objects.create(action="auth.login.succeeded", outcome="success")
    assert Api(bearer(team.platform_admin)).get("/api/v1/platform/audit-logs/").status_code == 403
    team.platform_admin.user_permissions.add(Permission.objects.get(codename="view_auditlog"))
    response = Api(bearer(User.objects.get(pk=team.platform_admin.pk))).get(
        "/api/v1/platform/audit-logs/"
    )
    assert response.status_code == 200
    assert all(r["organization"] is None for r in response.json()["results"])
