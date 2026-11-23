"""Tenant-isolation security matrix (ADR-0003 layers 1-6, ADR-0015).

Runs against the real project routes plus test-only tenant routes (``tests.fixtures_app``) built on
the same production primitives, so nested lookups, writes and body references are covered before
real tenant resources exist.
"""

import uuid
from collections.abc import Callable
from typing import Any

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import Client
from rest_framework.exceptions import NotFound
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from apps.accounts.models import User
from apps.accounts.tests.conftest import PASSWORD
from apps.audit.models import AuditLog
from apps.core import security_events
from apps.organizations.models import Membership, Organization
from apps.organizations.permissions import HasOrgPermission
from apps.organizations.scoping import (
    OrganizationScopedViewMixin,
    get_scoped_object_or_404,
)
from apps.organizations.tenancy import MissingTenantContextError
from tests.fixtures_app.models import TenantNote

from .conftest import Api, World, bearer

pytestmark = [pytest.mark.django_db, pytest.mark.urls("tests.fixtures_app.urls")]

MISSING_ORG = uuid.UUID("00000000-0000-4000-8000-000000000000")
PER_REQUEST_FIELDS = {"request_id"}


def org_url(org_id: Any, suffix: str = "") -> str:
    return f"/api/v1/organizations/{org_id}/{suffix}"


def notes_url(org_id: Any, note_id: Any = None) -> str:
    base = f"/test-api/organizations/{org_id}/notes/"
    return f"{base}{note_id}/" if note_id is not None else base


def comparable(response: Any) -> dict[str, Any]:
    body = {k: v for k, v in response.json().items() if k not in PER_REQUEST_FIELDS}
    return {"status": response.status_code, "body": body}


@pytest.fixture
def events() -> Any:
    captured: list[Any] = []
    unregister = security_events.register_sink(captured.append)
    yield captured
    unregister()


# ---------------------------------------------------------------------------- access matrix
CALLERS = ["alice", "bob", "carol", "dave", "erin", "platform_admin", "outsider"]
TARGETS = ["org_a", "org_b", "provisioning", "suspended", "missing"]
# Callers with an active membership in an active target organization.
MEMBERS = {("alice", "org_a"), ("bob", "org_b"), ("carol", "org_a"), ("carol", "org_b")}


def _target_id(world: World, target: str) -> Any:
    return MISSING_ORG if target == "missing" else getattr(world, target).pk


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("caller", CALLERS)
def test_access_matrix(world: World, api: Callable[..., Api], caller: str, target: str) -> None:
    client = api(getattr(world, caller))
    org_id = _target_id(world, target)
    member = (caller, target) in MEMBERS

    reads = [
        client.get(org_url(org_id)),
        client.get(org_url(org_id, "me/")),
        client.get(notes_url(org_id)),
    ]
    write = client.patch(org_url(org_id), {"name": "Renamed"})

    if member:
        assert [r.status_code for r in reads] == [200, 200, 200]
        # Membership alone never authorizes a write (default deny until Batch 6 roles).
        assert write.status_code == 403
        assert write.json()["code"] == "permission_denied"
    else:
        assert [r.status_code for r in [*reads, write]] == [404] * 4
    assert Organization.objects.filter(name="Renamed").count() == 0


@pytest.mark.parametrize("target", ["org_a", "missing"])
def test_anonymous_and_deactivated_callers_get_401(
    world: World, api: Callable[..., Api], target: str
) -> None:
    deactivated = Api(bearer(world.alice))
    User.objects.filter(pk=world.alice.pk).update(is_active=False)
    for client in (api(None), deactivated):
        for response in (
            client.get(org_url(_target_id(world, target))),
            client.get(org_url(_target_id(world, target), "me/")),
            client.get(notes_url(_target_id(world, target))),
            client.patch(org_url(_target_id(world, target)), {"name": "x"}),
            client.get("/api/v1/organizations/"),
        ):
            assert response.status_code == 401
            assert response["WWW-Authenticate"].startswith("Bearer")


def test_not_found_responses_disclose_nothing(world: World, api: Callable[..., Api]) -> None:
    """Unknown, foreign, provisioning, suspended and suspended-membership: one identical 404."""
    outcomes = [
        comparable(api(world.alice).get(org_url(MISSING_ORG))),
        comparable(api(world.alice).get(org_url(world.org_b.pk))),
        comparable(api(world.erin).get(org_url(world.provisioning.pk))),
        comparable(api(world.erin).get(org_url(world.suspended.pk))),
        comparable(api(world.dave).get(org_url(world.org_a.pk))),
        comparable(api(world.platform_admin).get(org_url(world.org_a.pk))),
    ]
    assert all(outcome == outcomes[0] for outcome in outcomes)
    assert outcomes[0]["status"] == 404
    assert outcomes[0]["body"]["code"] == "not_found"
    headers = [
        {k: v for k, v in api(world.alice).get(org_url(t)).items() if k.lower() != "x-request-id"}
        for t in (MISSING_ORG, world.org_b.pk)
    ]
    assert headers[0] == headers[1]


@pytest.mark.parametrize("bad_id", ["not-a-uuid", "1", "00000000-0000-0000-0000", "%00"])
def test_malformed_organization_ids_are_404(
    world: World, api: Callable[..., Api], bad_id: str
) -> None:
    response = api(world.alice).get(f"/api/v1/organizations/{bad_id}/")
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"


def test_denied_tenant_access_is_recorded(
    world: World, api: Callable[..., Api], events: Any
) -> None:
    api(world.alice).get(org_url(world.org_b.pk))
    [event] = [e for e in events if e.name == "tenant.access_denied"]
    assert event.outcome == "failure"
    assert event.user_id == str(world.alice.pk)
    row = AuditLog.objects.get(action="tenant.access_denied")
    # Platform-level record: it is not written into organization B's tenant history.
    assert row.organization_id is None
    assert (row.target_type, row.target_id) == ("organization", str(world.org_b.pk))
    assert row.actor_id == world.alice.pk


def test_context_is_the_url_organization(world: World, api: Callable[..., Api]) -> None:
    client = api(world.carol)
    for organization in (world.org_a, world.org_b):
        body = client.get(org_url(organization.pk, "me/")).json()
        assert body["organization"]["id"] == str(organization.pk)
        assert body["membership"]["status"] == "active"
    body = client.get(org_url(world.org_a.pk)).json()
    assert set(body) == {"id", "name", "slug", "organization_type", "timezone"}


# ----------------------------------------------------------------------- my organizations
@pytest.mark.parametrize(
    ("caller", "expected"),
    [
        ("alice", ["alpha"]),
        ("bob", ["beta"]),
        ("carol", ["alpha", "beta"]),
        ("dave", []),  # suspended membership
        ("erin", []),  # provisioning and suspended organizations
        ("platform_admin", []),  # platform status is not membership
        ("outsider", []),
    ],
)
def test_organization_listing(
    world: World, api: Callable[..., Api], caller: str, expected: list[str]
) -> None:
    body = api(getattr(world, caller)).get("/api/v1/organizations/").json()
    assert [entry["organization"]["slug"] for entry in body["results"]] == expected
    assert body["count"] == len(expected)
    for entry in body["results"]:
        assert set(entry) == {"organization", "membership"}
        assert set(entry["organization"]) == {"id", "name", "slug", "organization_type", "timezone"}
        assert set(entry["membership"]) == {"id", "status", "joined_at"}


def test_organization_listing_ordering_and_pagination(
    world: World, api: Callable[..., Api]
) -> None:
    client = api(world.carol)
    body = client.get("/api/v1/organizations/", data={"ordering": "-name"}).json()
    assert [e["organization"]["slug"] for e in body["results"]] == ["beta", "alpha"]
    body = client.get("/api/v1/organizations/", data={"page_size": 1}).json()
    assert (body["count"], len(body["results"]), body["total_pages"]) == (2, 1, 2)
    assert client.get("/api/v1/organizations/", data={"ordering": "status"}).status_code == 400


# ------------------------------------------------------------- nested lookups and writes
@pytest.fixture
def notes(world: World) -> dict[str, TenantNote]:
    return {
        "a": TenantNote.objects.create(organization=world.org_a, title="note-a"),
        "b": TenantNote.objects.create(organization=world.org_b, title="note-b"),
    }


class TestNestedIsolation:
    def test_lists_only_the_url_organization(
        self, world: World, api: Callable[..., Api], notes: dict[str, TenantNote]
    ) -> None:
        client = api(world.carol)  # member of both: isolation must come from the URL
        a = client.get(notes_url(world.org_a.pk)).json()["results"]
        b = client.get(notes_url(world.org_b.pk)).json()["results"]
        assert [n["title"] for n in a] == ["note-a"]
        assert [n["title"] for n in b] == ["note-b"]

    def test_foreign_object_under_own_url_is_404(
        self, world: World, api: Callable[..., Api], notes: dict[str, TenantNote]
    ) -> None:
        for caller in (world.alice, world.carol):
            client = api(caller)
            assert client.get(notes_url(world.org_a.pk, notes["a"].pk)).status_code == 200
            foreign = client.get(notes_url(world.org_a.pk, notes["b"].pk))
            missing = client.get(notes_url(world.org_a.pk, uuid.uuid4()))
            assert comparable(foreign) == comparable(missing)
            assert foreign.status_code == 404

    @pytest.mark.parametrize("note_id", ["not-a-uuid", "0", "%27%20OR%201%3D1"])
    def test_malformed_nested_ids_are_404(
        self, world: World, api: Callable[..., Api], note_id: str
    ) -> None:
        assert api(world.alice).get(notes_url(world.org_a.pk, note_id)).status_code == 404

    def test_cross_tenant_write_is_404_and_changes_nothing(
        self, world: World, api: Callable[..., Api], notes: dict[str, TenantNote]
    ) -> None:
        for caller in (world.alice, world.carol):
            response = api(caller).patch(notes_url(world.org_a.pk, notes["b"].pk), {"title": "x"})
            assert response.status_code == 404
        notes["b"].refresh_from_db()
        assert notes["b"].title == "note-b"

    def test_body_reference_to_another_organization_is_rejected(
        self, world: World, api: Callable[..., Api], notes: dict[str, TenantNote]
    ) -> None:
        client = api(world.carol)
        foreign = client.post(
            notes_url(world.org_a.pk), {"title": "x", "parent": str(notes["b"].pk)}
        )
        missing = client.post(
            notes_url(world.org_a.pk), {"title": "x", "parent": str(uuid.uuid4())}
        )
        assert foreign.status_code == missing.status_code == 400
        assert foreign.json()["errors"][0]["code"] == missing.json()["errors"][0]["code"]
        own = client.post(
            notes_url(world.org_a.pk), {"title": "child", "parent": str(notes["a"].pk)}
        )
        assert own.status_code == 201
        relink = client.patch(
            notes_url(world.org_a.pk, own.json()["id"]), {"parent": str(notes["b"].pk)}
        )
        assert relink.status_code == 400
        assert TenantNote.objects.get(pk=own.json()["id"]).parent_id == notes["a"].pk

    @pytest.mark.parametrize("key", ["organization", "organization_id", "org_id", "tenant"])
    def test_body_cannot_choose_the_organization(
        self, world: World, api: Callable[..., Api], notes: dict[str, TenantNote], key: str
    ) -> None:
        client = api(world.carol)
        created = client.post(
            notes_url(world.org_a.pk), {"title": "smuggled", key: str(world.org_b.pk)}
        )
        assert created.status_code == 400
        assert key in {e["pointer"].removeprefix("#/") for e in created.json()["errors"]}
        updated = client.patch(notes_url(world.org_a.pk, notes["a"].pk), {key: str(world.org_b.pk)})
        assert updated.status_code == 400
        assert not TenantNote.objects.filter(title="smuggled").exists()
        notes["a"].refresh_from_db()
        assert notes["a"].organization_id == world.org_a.pk

    def test_created_rows_belong_to_the_url_organization(
        self, world: World, api: Callable[..., Api]
    ) -> None:
        response = api(world.carol).post(notes_url(world.org_b.pk), {"title": "in-b"})
        assert response.status_code == 201
        assert TenantNote.objects.get(pk=response.json()["id"]).organization_id == world.org_b.pk

    def test_non_member_cannot_write(
        self, world: World, api: Callable[..., Api], notes: dict[str, TenantNote]
    ) -> None:
        assert api(world.bob).post(notes_url(world.org_a.pk), {"title": "x"}).status_code == 404
        assert api(world.dave).post(notes_url(world.org_a.pk), {"title": "x"}).status_code == 404
        assert TenantNote.objects.filter(title="x").count() == 0


# ------------------------------------------------------------------ primitives, fail closed
def test_scoped_queryset_fails_closed_without_context() -> None:
    class NoteView(OrganizationScopedViewMixin):
        tenant_model = TenantNote

    class Misconfigured(OrganizationScopedViewMixin):
        pass

    with pytest.raises(MissingTenantContextError):
        NoteView().get_scoped_queryset()
    with pytest.raises(ImproperlyConfigured):
        Misconfigured().get_scoped_queryset()


def test_scoped_object_lookup_fails_closed(world: World) -> None:
    note = TenantNote.objects.create(organization=world.org_a, title="n")
    assert get_scoped_object_or_404(TenantNote, world.org_a, pk=note.pk) == note
    with pytest.raises(NotFound):
        get_scoped_object_or_404(TenantNote, world.org_b, pk=note.pk)
    with pytest.raises(NotFound):
        get_scoped_object_or_404(TenantNote, world.org_a, pk="garbage")
    with pytest.raises(MissingTenantContextError):
        get_scoped_object_or_404(TenantNote, None, pk=note.pk)


class TestHasOrgPermission:
    def _request(self, method: str, membership: Any) -> Request:
        request = Request(getattr(APIRequestFactory(), method.lower())("/"))
        request.membership = membership  # type: ignore[attr-defined]
        return request

    def _view(self, **attrs: Any) -> Any:
        return type("View", (), attrs)()

    def test_default_deny(self, world: World) -> None:
        membership = Membership.objects.get(user=world.alice)
        permission = HasOrgPermission()
        assert not permission.has_permission(self._request("GET", membership), self._view())
        assert not permission.has_permission(self._request("POST", membership), self._view())

    def test_member_actions_only_cover_safe_methods(self, world: World) -> None:
        membership = Membership.objects.get(user=world.alice)
        view = self._view(member_actions=("get", "post", "delete"))
        permission = HasOrgPermission()
        assert permission.has_permission(self._request("GET", membership), view)
        assert not permission.has_permission(self._request("POST", membership), view)
        assert not permission.has_permission(self._request("DELETE", membership), view)

    def test_declared_permissions_fail_closed_until_rbac(self, world: World) -> None:
        membership = Membership.objects.get(user=world.alice)
        view = self._view(required_permissions={"post": ("organization.update",)})
        assert not HasOrgPermission().has_permission(self._request("POST", membership), view)

    def test_no_membership_no_access(self) -> None:
        view = self._view(member_actions=("get",))
        assert not HasOrgPermission().has_permission(self._request("GET", None), view)


def test_platform_admin_has_no_tenant_bypass_even_with_superuser(
    world: World, api: Callable[..., Api]
) -> None:
    root = User.objects.create_superuser("root@example.org", PASSWORD, full_name="R")
    client = api(root)
    for organization in (world.org_a, world.org_b):
        assert client.get(org_url(organization.pk)).status_code == 404
        assert client.get(notes_url(organization.pk)).status_code == 404
    assert client.get("/api/v1/organizations/").json()["count"] == 0


def test_tenant_header_is_ignored(world: World) -> None:
    """Only the URL selects the tenant; headers such as X-Organization-Id are never consulted."""
    headers: dict[str, Any] = {**bearer(world.alice), "HTTP_X_ORGANIZATION_ID": str(world.org_b.pk)}
    response = Client().get(org_url(world.org_a.pk, "me/"), **headers)
    assert response.json()["organization"]["id"] == str(world.org_a.pk)
    assert Client().get(org_url(world.org_b.pk), **headers).status_code == 404


def test_non_object_json_bodies_are_validated_normally(world: World) -> None:
    response = Client().post(
        notes_url(world.org_a.pk), "[1, 2]", content_type="application/json", **bearer(world.alice)
    )
    assert response.status_code == 400
