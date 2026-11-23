"""Audit read APIs: authorization, tenant isolation, filters and cursor pagination."""

import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from django.contrib.auth.models import Permission
from django.db import connection
from django.utils import timezone

from apps.accounts.models import User
from apps.audit.models import AuditLog
from apps.organizations.tests.conftest import Api, World

pytestmark = [pytest.mark.django_db, pytest.mark.urls("tests.fixtures_app.urls")]

MISSING_ORG = uuid.UUID("00000000-0000-4000-8000-000000000000")
PLATFORM_URL = "/api/v1/platform/audit-logs/"


def tenant_url(org_id: Any) -> str:
    return f"/api/v1/organizations/{org_id}/audit-logs/"


def scoping_url(org_id: Any) -> str:
    """The production view with a test-only permission (Batch 6 adds audit.view)."""
    return f"/test-api/organizations/{org_id}/audit-logs/"


def _insert(action: str, organization: Any = None, actor: Any = None, **extra: Any) -> AuditLog:
    """Append a row directly (test data); created_at may be set explicitly."""
    entry = AuditLog(
        action=action,
        outcome=extra.pop("outcome", "success"),
        organization=organization,
        actor=actor,
        actor_email=getattr(actor, "email", ""),
        **extra,
    )
    entry.save(force_insert=True)
    return entry


@pytest.fixture
def history(world: World) -> dict[str, AuditLog]:
    now = timezone.now()
    return {
        "a1": _insert(
            "organization.updated", world.org_a, world.alice, created_at=now - timedelta(days=2)
        ),
        "a2": _insert(
            "member.example",
            world.org_a,
            world.carol,
            outcome="failure",
            created_at=now - timedelta(days=1),
        ),
        "b1": _insert("organization.updated", world.org_b, world.bob, created_at=now),
        "platform": _insert("auth.login.failed", None, None, outcome="failure", created_at=now),
    }


# ----------------------------------------------------------------- tenant endpoint (prod)
CALLERS = ["alice", "bob", "carol", "dave", "erin", "platform_admin", "outsider"]
TARGETS = ["org_a", "org_b", "provisioning", "suspended", "missing"]
MEMBERS = {("alice", "org_a"), ("bob", "org_b"), ("carol", "org_a"), ("carol", "org_b")}


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("caller", CALLERS)
def test_tenant_audit_endpoint_fails_closed(
    world: World, api: Callable[..., Api], history: Any, caller: str, target: str
) -> None:
    org_id = MISSING_ORG if target == "missing" else getattr(world, target).pk
    response = api(getattr(world, caller)).get(tenant_url(org_id))
    if (caller, target) in MEMBERS:
        # Members exist, but no one can hold audit.view before Batch 6 roles.
        assert response.status_code == 403
        assert response.json()["code"] == "permission_denied"
    else:
        assert response.status_code == 404
        assert response.json()["code"] == "not_found"
    assert "organization.updated" not in response.content.decode()


def test_tenant_audit_endpoint_requires_authentication(
    world: World, api: Callable[..., Api]
) -> None:
    assert api(None).get(tenant_url(world.org_a.pk)).status_code == 401
    root = User.objects.create_superuser(
        "root@example.org", "Correct-Horse-Battery-42", full_name="R"
    )
    assert api(root).get(tenant_url(world.org_a.pk)).status_code == 404  # no superuser bypass
    assert api(world.alice).get("/api/v1/organizations/not-a-uuid/audit-logs/").status_code == 404


# ------------------------------------------------- tenant scoping (production view, test perm)
class TestTenantScoping:
    def test_only_the_url_organization_is_returned(
        self, world: World, api: Callable[..., Api], history: dict[str, AuditLog]
    ) -> None:
        client = api(world.carol)  # member of both organizations
        a = client.get(scoping_url(world.org_a.pk)).json()["results"]
        b = client.get(scoping_url(world.org_b.pk)).json()["results"]
        assert [r["id"] for r in a] == [
            str(history["a2"].pk),
            str(history["a1"].pk),
        ]  # newest first
        assert [r["id"] for r in b] == [str(history["b1"].pk)]
        assert all(r["organization"] == str(world.org_a.pk) for r in a)

    def test_null_organization_events_never_appear_in_a_tenant(
        self, world: World, api: Callable[..., Api], history: dict[str, AuditLog]
    ) -> None:
        body = api(world.alice).get(scoping_url(world.org_a.pk)).content.decode()
        assert str(history["platform"].pk) not in body
        assert str(history["b1"].pk) not in body

    def test_non_members_still_get_404(self, world: World, api: Callable[..., Api]) -> None:
        for caller in (world.bob, world.dave, world.platform_admin):
            assert api(caller).get(scoping_url(world.org_a.pk)).status_code == 404

    def test_filters(
        self, world: World, api: Callable[..., Api], history: dict[str, AuditLog]
    ) -> None:
        client = api(world.carol)
        url = scoping_url(world.org_a.pk)

        def ids(**params: Any) -> list[str]:
            return [r["id"] for r in client.get(url, data=params).json()["results"]]

        assert ids(action="member.example") == [str(history["a2"].pk)]
        assert ids(outcome="failure") == [str(history["a2"].pk)]
        assert ids(actor=str(world.alice.pk)) == [str(history["a1"].pk)]
        day = timezone.now() - timedelta(hours=36)
        assert ids(created_after=day.isoformat()) == [str(history["a2"].pk)]
        assert ids(created_before=day.isoformat()) == [str(history["a1"].pk)]
        # Values from another tenant match nothing here.
        assert ids(actor=str(world.bob.pk)) == []
        assert ids(action="auth.login.failed") == []

    @pytest.mark.parametrize(
        "params", [{"actor": "nope"}, {"outcome": "maybe"}, {"created_after": "yesterday"}]
    )
    def test_invalid_filter_values_are_400(
        self, world: World, api: Callable[..., Api], params: dict[str, str]
    ) -> None:
        response = api(world.alice).get(scoping_url(world.org_a.pk), data=params)
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_query_parameters"

    def test_cursor_pagination_is_stable_and_bounded(
        self, world: World, api: Callable[..., Api]
    ) -> None:
        same_time = timezone.now()
        inserted = {_insert("bulk.event", world.org_a, created_at=same_time).pk for _ in range(7)}
        client = api(world.alice)
        seen: list[str] = []
        url: str | None = scoping_url(world.org_a.pk) + "?page_size=3"
        while url:
            body = client.get(url).json()
            assert set(body) == {"next", "previous", "results"}
            assert len(body["results"]) <= 3
            seen += [r["id"] for r in body["results"]]
            url = body["next"]
        assert len(seen) == len(set(seen)) == 7
        assert set(seen) == {str(pk) for pk in inserted}
        capped = client.get(scoping_url(world.org_a.pk), data={"page_size": 10_000}).json()
        assert len(capped["results"]) == 7  # cap is 100; all fit
        assert (
            client.get(scoping_url(world.org_a.pk), data={"cursor": "garbage"}).status_code == 404
        )

    def test_response_shape(self, world: World, api: Callable[..., Api], history: Any) -> None:
        [entry, *_] = api(world.alice).get(scoping_url(world.org_a.pk)).json()["results"]
        assert set(entry) == {
            "id",
            "created_at",
            "action",
            "outcome",
            "organization",
            "actor",
            "actor_email",
            "target_type",
            "target_id",
            "changes",
            "metadata",
            "ip_address",
            "user_agent",
            "request_id",
        }


# ------------------------------------------------------------------- platform endpoint
@pytest.fixture
def auditor(make_user: Callable[..., User]) -> User:
    user = make_user("auditor@example.org", is_staff=True)
    user.user_permissions.add(Permission.objects.get(codename="view_auditlog"))
    return User.objects.get(pk=user.pk)


class TestPlatformEndpoint:
    def test_authorization(
        self, world: World, api: Callable[..., Api], auditor: User, make_user: Callable[..., User]
    ) -> None:
        assert api(None).get(PLATFORM_URL).status_code == 401
        assert api(world.alice).get(PLATFORM_URL).status_code == 403
        assert api(make_user(is_staff=True)).get(PLATFORM_URL).status_code == 403
        # Organization administrators are not auditors.
        assert api(world.platform_admin).get(PLATFORM_URL).status_code == 403
        non_staff = make_user()
        non_staff.user_permissions.add(Permission.objects.get(codename="view_auditlog"))
        assert api(User.objects.get(pk=non_staff.pk)).get(PLATFORM_URL).status_code == 403
        assert api(auditor).get(PLATFORM_URL).status_code == 200
        User.objects.filter(pk=auditor.pk).update(is_active=False)

    def test_only_platform_events_are_served(
        self, api: Callable[..., Api], auditor: User, history: dict[str, AuditLog]
    ) -> None:
        body = api(auditor).get(PLATFORM_URL).json()
        ids = {r["id"] for r in body["results"]}
        assert str(history["platform"].pk) in ids
        assert not ids & {str(history[k].pk) for k in ("a1", "a2", "b1")}
        assert all(r["organization"] is None for r in body["results"])

    def test_filters(self, api: Callable[..., Api], auditor: User, history: Any) -> None:
        client = api(auditor)
        results = client.get(PLATFORM_URL, data={"action": "auth.login.failed"}).json()["results"]
        assert [r["id"] for r in results] == [str(history["platform"].pk)]
        assert (
            client.get(PLATFORM_URL, data={"action": "organization.updated"}).json()["results"]
            == []
        )

    def test_post_is_not_allowed(self, api: Callable[..., Api], auditor: User) -> None:
        assert api(auditor).post(PLATFORM_URL, {}).status_code in {403, 405}


def test_audit_rows_carry_no_tenant_data_for_null_organizations(world: World, api: Any) -> None:
    """tenant.access_denied stays out of the target organization's history."""
    api(world.alice).get(f"/api/v1/organizations/{world.org_b.pk}/")
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT organization_id, target_id FROM audit_auditlog WHERE action = %s",
            ["tenant.access_denied"],
        )
        assert cursor.fetchall() == [(None, str(world.org_b.pk))]
