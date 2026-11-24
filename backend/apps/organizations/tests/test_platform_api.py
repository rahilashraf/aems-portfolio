"""Platform organization administration: authorization, creation, lifecycle, validation."""

from collections.abc import Callable
from typing import Any

import pytest
from django.contrib.auth.models import Permission

from apps.accounts.models import User
from apps.accounts.tests.conftest import PASSWORD
from apps.audit.models import AuditLog
from apps.core import security_events
from apps.organizations.models import Membership, Organization, OrganizationStatus

from .conftest import Api, World, add_default_member, error_fields

pytestmark = pytest.mark.django_db
LIST_URL = "/api/v1/platform/organizations/"
NEW_ORG = {
    "name": "Northfield Academy",
    "slug": "Northfield",
    "organization_type": "school",
    "initial_owner_email": "head@northfield.example.org",
}


def detail(organization: Organization) -> str:
    return f"{LIST_URL}{organization.pk}/"


def _events(captured: list[Any], name: str) -> list[Any]:
    return [e for e in captured if e.name == name]


@pytest.fixture
def events() -> Any:
    captured: list[Any] = []
    unregister = security_events.register_sink(captured.append)
    yield captured
    unregister()


class TestAuthorization:
    def test_anonymous_gets_401(self, api: Callable[..., Api]) -> None:
        assert api(None).get(LIST_URL).status_code == 401
        assert api(None).post(LIST_URL, NEW_ORG).status_code == 401

    def test_members_and_plain_users_are_denied(
        self, world: World, api: Callable[..., Api]
    ) -> None:
        for user in (world.alice, world.carol, world.outsider):
            assert api(user).get(LIST_URL).status_code == 403
            assert api(user).post(LIST_URL, NEW_ORG).status_code == 403
            assert api(user).get(detail(world.org_a)).status_code == 403
            assert api(user).patch(detail(world.org_a), {"name": "x"}).status_code == 403

    def test_staff_without_model_permissions_is_denied(
        self, world: World, make_user: Callable[..., User], api: Callable[..., Api]
    ) -> None:
        staff = make_user(is_staff=True)
        assert api(staff).get(LIST_URL).status_code == 403
        assert api(staff).post(LIST_URL, NEW_ORG).status_code == 403

    def test_permissions_are_per_method(
        self, world: World, make_user: Callable[..., User], api: Callable[..., Api]
    ) -> None:
        viewer = make_user(is_staff=True)
        viewer.user_permissions.add(Permission.objects.get(codename="view_organization"))
        viewer = User.objects.get(pk=viewer.pk)
        assert api(viewer).get(LIST_URL).status_code == 200
        assert api(viewer).get(detail(world.org_a)).status_code == 200
        assert api(viewer).post(LIST_URL, NEW_ORG).status_code == 403
        assert api(viewer).patch(detail(world.org_a), {"name": "x"}).status_code == 403

    def test_permissions_without_staff_are_denied(
        self, make_user: Callable[..., User], api: Callable[..., Api]
    ) -> None:
        user = make_user()
        user.user_permissions.add(
            *Permission.objects.filter(content_type__app_label="organizations")
        )
        assert api(User.objects.get(pk=user.pk)).get(LIST_URL).status_code == 403

    def test_superuser_is_a_platform_administrator(
        self, make_user: Callable[..., User], api: Callable[..., Api]
    ) -> None:
        root = User.objects.create_superuser("root@example.org", PASSWORD, full_name="Root")
        assert api(root).post(LIST_URL, NEW_ORG).status_code == 201


class TestCreate:
    def test_creates_in_provisioning(
        self,
        platform_admin: User,
        api: Callable[..., Api],
        events: list[Any],
        django_capture_on_commit_callbacks: Any,
    ) -> None:
        with django_capture_on_commit_callbacks(execute=True):
            response = api(platform_admin).post(LIST_URL, {**NEW_ORG, "timezone": "Europe/London"})
        assert response.status_code == 201
        body = response.json()
        assert body["status"] == "provisioning"
        assert body["slug"] == "northfield"  # normalized
        assert body["timezone"] == "Europe/London"
        assert body["created_by"] == str(platform_admin.pk)
        organization = Organization.objects.get(pk=body["id"])
        assert organization.status == OrganizationStatus.PROVISIONING
        [event] = _events(events, "organization.created")
        assert event.user_id == str(platform_admin.pk)
        assert event.metadata["organization_id"] == body["id"]
        assert event.metadata["status"] == "provisioning"
        row = AuditLog.objects.get(action="organization.created")
        assert str(row.organization_id) == body["id"]
        assert (row.actor_id, row.actor_email) == (platform_admin.pk, platform_admin.email)
        assert row.metadata == {"status": "provisioning"}

    def test_defaults_timezone_to_utc(self, platform_admin: User, api: Callable[..., Api]) -> None:
        assert api(platform_admin).post(LIST_URL, NEW_ORG).json()["timezone"] == "UTC"

    def test_creator_gets_no_membership(
        self, platform_admin: User, api: Callable[..., Api]
    ) -> None:
        body = api(platform_admin).post(LIST_URL, NEW_ORG).json()
        assert not Membership.objects.filter(user=platform_admin).exists()
        assert api(platform_admin).get(f"/api/v1/organizations/{body['id']}/").status_code == 404

    @pytest.mark.parametrize(
        "field", ["status", "id", "created_by", "created_at", "organization", "owner"]
    )
    def test_restricted_fields_are_rejected(
        self, platform_admin: User, api: Callable[..., Api], field: str
    ) -> None:
        response = api(platform_admin).post(LIST_URL, {**NEW_ORG, field: "active"})
        assert response.status_code == 400
        assert field in error_fields(response)
        assert not Organization.objects.exists()

    @pytest.mark.parametrize(
        ("payload", "field"),
        [
            ({**NEW_ORG, "slug": "a b"}, "slug"),
            ({**NEW_ORG, "slug": "ab"}, "slug"),
            ({**NEW_ORG, "timezone": "Mars/Base"}, "timezone"),
            ({**NEW_ORG, "organization_type": "company"}, "organization_type"),
            ({**NEW_ORG, "name": "   "}, "name"),
            ({"slug": "only-slug", "organization_type": "school"}, "name"),
        ],
    )
    def test_validation(
        self, platform_admin: User, api: Callable[..., Api], payload: dict[str, str], field: str
    ) -> None:
        response = api(platform_admin).post(LIST_URL, payload)
        assert response.status_code == 400
        assert response.json()["code"] == "validation_error"
        assert field in error_fields(response)

    def test_duplicate_slug_is_409(self, platform_admin: User, api: Callable[..., Api]) -> None:
        assert api(platform_admin).post(LIST_URL, NEW_ORG).status_code == 201
        response = api(platform_admin).post(LIST_URL, {**NEW_ORG, "slug": " NORTHFIELD "})
        assert response.status_code == 409
        assert response.json()["code"] == "organization_slug_taken"


class TestListAndRetrieve:
    def test_lists_all_organizations_with_pagination(
        self, world: World, platform_admin: User, api: Callable[..., Api]
    ) -> None:
        body = api(platform_admin).get(LIST_URL, data={"page_size": 2}).json()
        assert body["count"] == 4
        assert len(body["results"]) == 2
        assert [o["name"] for o in body["results"]] == sorted(o["name"] for o in body["results"])

    def test_filters_and_ordering(
        self, world: World, platform_admin: User, api: Callable[..., Api]
    ) -> None:
        body = api(platform_admin).get(LIST_URL, data={"status": "provisioning"}).json()
        assert [o["slug"] for o in body["results"]] == ["pending"]
        body = api(platform_admin).get(LIST_URL, data={"ordering": "-slug"}).json()
        assert [o["slug"] for o in body["results"]] == ["pending", "paused", "beta", "alpha"]
        assert api(platform_admin).get(LIST_URL, data={"ordering": "created_by"}).status_code == 400
        assert api(platform_admin).get(LIST_URL, data={"status": "bogus"}).status_code == 400

    def test_detail_and_unknown_id(
        self, world: World, platform_admin: User, api: Callable[..., Api]
    ) -> None:
        assert api(platform_admin).get(detail(world.org_a)).json()["slug"] == "alpha"
        response = api(platform_admin).get(f"{LIST_URL}00000000-0000-4000-8000-000000000000/")
        assert response.status_code == 404
        assert api(platform_admin).get(f"{LIST_URL}not-a-uuid/").status_code == 404


class TestUpdateAndLifecycle:
    def test_updates_editable_fields(
        self,
        world: World,
        platform_admin: User,
        api: Callable[..., Api],
        events: list[Any],
        django_capture_on_commit_callbacks: Any,
    ) -> None:
        with django_capture_on_commit_callbacks(execute=True):
            response = api(platform_admin).patch(
                detail(world.org_a),
                {
                    "name": "Alpha College",
                    "timezone": "Asia/Tokyo",
                    "organization_type": "university",
                },
            )
        assert response.status_code == 200
        world.org_a.refresh_from_db()
        assert (world.org_a.name, world.org_a.timezone) == ("Alpha College", "Asia/Tokyo")
        [event] = _events(events, "organization.updated")
        assert event.metadata["changed_fields"] == ["name", "organization_type", "timezone"]

    def test_no_op_update_records_nothing(
        self,
        world: World,
        platform_admin: User,
        api: Callable[..., Api],
        events: list[Any],
        django_capture_on_commit_callbacks: Any,
    ) -> None:
        with django_capture_on_commit_callbacks(execute=True):
            response = api(platform_admin).patch(detail(world.org_a), {"name": world.org_a.name})
        assert response.status_code == 200
        assert _events(events, "organization.updated") == []

    @pytest.mark.parametrize("field", ["slug", "id", "created_by", "created_at", "organization_id"])
    def test_immutable_fields_are_rejected(
        self, world: World, platform_admin: User, api: Callable[..., Api], field: str
    ) -> None:
        response = api(platform_admin).patch(detail(world.org_a), {field: "new-value"})
        assert response.status_code == 400
        world.org_a.refresh_from_db()
        assert world.org_a.slug == "alpha"

    @pytest.mark.parametrize(
        ("start", "target"),
        [
            ("provisioning", "active"),
            ("suspended", "active"),
            ("provisioning", "suspended"),
            ("active", "provisioning"),
            ("suspended", "provisioning"),
        ],
    )
    def test_disallowed_transitions_are_409(
        self, world: World, platform_admin: User, api: Callable[..., Api], start: str, target: str
    ) -> None:
        organization = {
            "provisioning": world.provisioning,
            "active": world.org_a,
            "suspended": world.suspended,
        }[start]
        response = api(platform_admin).patch(detail(organization), {"status": target})
        assert response.status_code == 409
        assert response.json()["code"] == "organization_status_transition_not_allowed"
        organization.refresh_from_db()
        assert organization.status == start

    def test_rejected_transition_leaves_other_changes_unapplied(
        self, world: World, platform_admin: User, api: Callable[..., Api]
    ) -> None:
        response = api(platform_admin).patch(
            detail(world.provisioning), {"status": "active", "name": "Renamed"}
        )
        assert response.status_code == 409
        world.provisioning.refresh_from_db()
        assert world.provisioning.name != "Renamed"

    def test_suspension_is_immediate_for_tenant_apis(
        self,
        world: World,
        platform_admin: User,
        api: Callable[..., Api],
        events: list[Any],
        django_capture_on_commit_callbacks: Any,
    ) -> None:
        alice = api(world.alice)
        assert alice.get(f"/api/v1/organizations/{world.org_a.pk}/").status_code == 200
        with django_capture_on_commit_callbacks(execute=True):
            response = api(platform_admin).patch(detail(world.org_a), {"status": "suspended"})
        assert response.status_code == 200
        assert response.json()["status"] == "suspended"
        # Same access token, next request: closed.
        assert alice.get(f"/api/v1/organizations/{world.org_a.pk}/").status_code == 404
        assert alice.get("/api/v1/organizations/").json()["count"] == 0
        [event] = _events(events, "organization.status_changed")
        assert event.metadata["previous_status"] == "active"
        assert event.metadata["status"] == "suspended"
        # And it cannot be reactivated here.
        assert (
            api(platform_admin).patch(detail(world.org_a), {"status": "active"}).status_code == 409
        )

    def test_same_status_is_a_no_op(
        self, world: World, platform_admin: User, api: Callable[..., Api]
    ) -> None:
        response = api(platform_admin).patch(detail(world.provisioning), {"status": "provisioning"})
        assert response.status_code == 200


def test_platform_admin_with_membership_still_follows_tenant_rules(
    world: World, platform_admin: User, api: Callable[..., Api]
) -> None:
    """Platform status adds nothing inside a tenant: a membership is needed, and it is checked."""
    add_default_member(world.org_b, platform_admin)
    client = api(platform_admin)
    assert client.get(f"/api/v1/organizations/{world.org_b.pk}/").status_code == 200
    assert client.get(f"/api/v1/organizations/{world.org_a.pk}/").status_code == 404
    assert (
        client.patch(f"/api/v1/organizations/{world.org_b.pk}/", {"name": "x"}).status_code == 403
    )
