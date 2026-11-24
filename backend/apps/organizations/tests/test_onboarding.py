"""Initial Owner onboarding: creation, the closed provisioning state, platform reissue and revoke,
and activation through acceptance as the only provisioning → active path (ADR-0018)."""

from collections.abc import Callable
from typing import Any

import pytest
from django.contrib.auth.models import Permission as DjangoPermission
from django.core import mail
from django.db import DatabaseError

from apps.accounts.models import User
from apps.audit.models import AuditLog
from apps.organizations.models import (
    Invitation,
    InvitationStatus,
    Membership,
    Organization,
    OrganizationStatus,
)
from apps.organizations.services import create_organization
from apps.rbac.models import MembershipRole, SystemRole

from .conftest import Api, activate_for_tests
from .invitation_helpers import accept, deliver, new_account_body, preview

pytestmark = pytest.mark.django_db
PLATFORM = "/api/v1/platform/organizations/"
BODY = {
    "name": "Riverside School",
    "slug": "riverside",
    "organization_type": "school",
    "initial_owner_email": "Head@Riverside.Example.ORG",
}


def initial_url(organization_id: Any, suffix: str = "") -> str:
    return f"{PLATFORM}{organization_id}/initial-owner-invitation/{suffix}"


@pytest.fixture
def created(platform_admin: User, api: Callable[..., Api]) -> Organization:
    response = api(platform_admin).post(PLATFORM, BODY)
    assert response.status_code == 201, response.content
    return Organization.objects.get(pk=response.json()["id"])


def actions(organization: Organization) -> list[str]:
    return list(
        AuditLog.objects.filter(organization=organization)
        .order_by("created_at", "id")
        .values_list("action", flat=True)
    )


class TestCreation:
    def test_creation_issues_the_initial_owner_invitation(
        self, created: Organization, platform_admin: User
    ) -> None:
        assert created.status == OrganizationStatus.PROVISIONING
        [invitation] = Invitation.objects.filter(organization=created)
        assert invitation.is_initial_owner
        assert invitation.email == "head@riverside.example.org"  # normalized
        assert invitation.invited_by_id == platform_admin.pk
        assert [link.role.system_key for link in invitation.role_links.all()] == ["owner"]
        assert invitation.token_hash is None  # no token until the email is sent
        assert invitation.email_delivery.status == "pending"
        assert not Membership.objects.filter(organization=created).exists()
        assert actions(created) == ["organization.created", "invitation.initial_owner_issued"]
        assert mail.outbox == []  # nothing is sent inside the request

    @pytest.mark.parametrize(
        "change", [{"initial_owner_email": "not-an-email"}, {"initial_owner_email": ""}, None]
    )
    def test_invalid_or_missing_owner_email_creates_nothing(
        self, platform_admin: User, api: Callable[..., Api], change: dict[str, str] | None
    ) -> None:
        body = {**BODY, **change} if change else {k: v for k, v in BODY.items() if "owner" not in k}
        assert api(platform_admin).post(PLATFORM, body).status_code == 400
        assert not Organization.objects.exists()
        assert not Invitation.objects.exists()

    def test_any_failure_rolls_back_the_whole_creation(
        self, platform_admin: User, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def broken(*_args: Any, **_kwargs: Any) -> None:
            raise DatabaseError("audit storage unavailable")

        monkeypatch.setattr(AuditLog, "save", broken)
        with pytest.raises(DatabaseError):
            create_organization(
                actor=platform_admin,
                name="X",
                slug="x-org",
                organization_type="other",
                initial_owner_email="o@example.org",
            )
        monkeypatch.undo()
        assert not Organization.objects.exists()
        assert not Invitation.objects.exists()

    def test_provisioning_organization_stays_closed(
        self, created: Organization, platform_admin: User, api: Callable[..., Api]
    ) -> None:
        for path in ("", "me/", "members/", "invitations/", "roles/"):
            response = api(platform_admin).get(f"/api/v1/organizations/{created.pk}/{path}")
            assert response.status_code == 404
        # There is no manual activation.
        response = api(platform_admin).patch(f"{PLATFORM}{created.pk}/", {"status": "active"})
        assert response.status_code == 409
        created.refresh_from_db()
        assert created.status == OrganizationStatus.PROVISIONING


class TestActivation:
    def test_new_account_accepts_and_activates(
        self, created: Organization, api: Callable[..., Api]
    ) -> None:
        tokens = deliver()
        token = tokens["head@riverside.example.org"]
        message = mail.outbox[-1]
        assert "Riverside School" in message.subject
        assert "Owner" in message.body
        assert "expires" in message.body
        assert "password" in message.body.lower()  # instructions; never an actual password
        assert preview(token).json()["organization_name"] == "Riverside School"

        response = accept(token, new_account_body("Head Teacher"))
        assert response.status_code == 200, response.content
        body = response.json()
        assert body["organization"] == {
            "id": str(created.pk),
            "name": "Riverside School",
            "status": "active",
        }
        assert body["account_created"] is True
        assert [r["system_key"] for r in body["roles"]] == ["owner"]

        created.refresh_from_db()
        assert created.status == OrganizationStatus.ACTIVE
        owner = User.objects.get(email="head@riverside.example.org")
        assert owner.check_password("Correct-Horse-Battery-Staple-42")
        assert not owner.is_staff
        assert MembershipRole.objects.filter(
            organization=created, membership__user=owner, role__system_key=SystemRole.OWNER
        ).exists()
        assert actions(created)[-5:] == [
            "invitation.accepted",
            "rbac.membership.created",
            "rbac.membership.roles_assigned",
            "rbac.owner.granted",
            "organization.activated",
        ]
        # The new Owner now uses the tenant API normally.
        me = api(owner).get(f"/api/v1/organizations/{created.pk}/me/").json()
        assert me["roles"][0]["system_key"] == "owner"
        assert accept(token, new_account_body()).status_code == 404  # single use

    def test_existing_account_signs_in_to_accept(
        self, created: Organization, make_user: Callable[..., User]
    ) -> None:
        head = make_user("head@riverside.example.org")
        token = deliver()[head.email]
        assert accept(token).json()["code"] == "sign_in_required"
        assert accept(token, user=head).status_code == 200
        created.refresh_from_db()
        assert created.status == OrganizationStatus.ACTIVE

    def test_failed_activation_leaves_everything_provisioning(
        self, created: Organization, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        token = deliver()["head@riverside.example.org"]
        real_save = AuditLog.save

        def fail_on_activation(entry: AuditLog, *args: Any, **kwargs: Any) -> None:
            if entry.action == "organization.activated":
                raise DatabaseError("audit storage unavailable")
            real_save(entry, *args, **kwargs)

        monkeypatch.setattr(AuditLog, "save", fail_on_activation)
        assert accept(token, new_account_body(), raise_errors=False).status_code == 500
        monkeypatch.undo()
        created.refresh_from_db()
        assert created.status == OrganizationStatus.PROVISIONING
        assert not User.objects.filter(email="head@riverside.example.org").exists()
        assert not Membership.objects.filter(organization=created).exists()
        assert Invitation.objects.get(organization=created).status == InvitationStatus.PENDING
        assert accept(token, new_account_body()).status_code == 200  # still usable

    def test_suspended_organization_is_not_reactivated_by_an_old_invitation(
        self, created: Organization
    ) -> None:
        token = deliver()["head@riverside.example.org"]
        Organization.objects.filter(pk=created.pk).update(status=OrganizationStatus.SUSPENDED)
        assert accept(token, new_account_body()).status_code == 404
        assert preview(token).status_code == 404
        created.refresh_from_db()
        assert created.status == OrganizationStatus.SUSPENDED


class TestPlatformManagement:
    def test_view_reissue_and_revoke(
        self, created: Organization, platform_admin: User, api: Callable[..., Api]
    ) -> None:
        client = api(platform_admin)
        first = client.get(initial_url(created.pk)).json()
        assert first["email"] == "head@riverside.example.org"
        assert "token" not in str(first).lower()
        old_token = deliver()["head@riverside.example.org"]

        reissued = client.post(initial_url(created.pk), {"email": "Deputy@Riverside.example.org"})
        assert reissued.status_code == 201
        assert reissued.json()["email"] == "deputy@riverside.example.org"
        assert Invitation.objects.get(pk=first["id"]).status == InvitationStatus.REVOKED
        assert preview(old_token).status_code == 404  # the revoked link is dead
        new_token = deliver()["deputy@riverside.example.org"]

        revoked = client.post(initial_url(created.pk, "revoke/"))
        assert revoked.status_code == 200
        assert revoked.json()["status"] == "revoked"
        assert accept(new_token, new_account_body()).status_code == 404
        assert client.get(initial_url(created.pk)).status_code == 404
        assert client.post(initial_url(created.pk, "revoke/")).status_code == 404
        assert actions(created).count("invitation.revoked") == 2

    def test_pre_batch_7_organization_gets_its_first_invitation(
        self, platform_admin: User, api: Callable[..., Api]
    ) -> None:
        legacy = Organization.objects.create(
            name="Legacy", slug="legacy", organization_type="other", created_by=platform_admin
        )
        from apps.rbac.services import seed_system_roles  # noqa: PLC0415

        seed_system_roles(legacy)
        response = api(platform_admin).post(initial_url(legacy.pk), {"email": "o@legacy.org"})
        assert response.status_code == 201
        assert accept(deliver()["o@legacy.org"], new_account_body()).status_code == 200
        legacy.refresh_from_db()
        assert legacy.status == OrganizationStatus.ACTIVE

    def test_only_for_provisioning_organizations(
        self, make_org: Callable[..., Organization], platform_admin: User, api: Callable[..., Api]
    ) -> None:
        active = make_org()
        client = api(platform_admin)
        response = client.post(initial_url(active.pk), {"email": "x@example.org"})
        assert response.status_code == 409
        assert response.json()["code"] == "organization_not_provisioning"
        assert client.post(initial_url(active.pk, "revoke/")).status_code == 409
        assert client.get(initial_url(active.pk)).status_code == 404
        assert (
            client.post(
                initial_url("00000000-0000-4000-8000-000000000000"), {"email": "a@b.co"}
            ).status_code
            == 404
        )

    def test_explicit_permissions_are_required(
        self, created: Organization, make_user: Callable[..., User], api: Callable[..., Api]
    ) -> None:
        staff = make_user(is_staff=True)
        staff.user_permissions.add(DjangoPermission.objects.get(codename="view_organization"))
        staff = User.objects.get(pk=staff.pk)
        assert api(staff).get(initial_url(created.pk)).status_code == 200
        assert (
            api(staff).post(initial_url(created.pk), {"email": "x@example.org"}).status_code == 403
        )
        assert api(staff).post(initial_url(created.pk, "revoke/")).status_code == 403
        assert api(None).get(initial_url(created.pk)).status_code == 401
        plain = make_user()
        assert api(plain).get(initial_url(created.pk)).status_code == 403
        # Holding the permission without staff status is not enough either.
        nonstaff = make_user()
        nonstaff.user_permissions.add(
            DjangoPermission.objects.get(codename="manage_initial_owner_invitation")
        )
        nonstaff = User.objects.get(pk=nonstaff.pk)
        assert (
            api(nonstaff).post(initial_url(created.pk), {"email": "x@example.org"}).status_code
            == 403
        )

    def test_permission_is_rechecked_inside_the_transaction(
        self, created: Organization, platform_admin: User
    ) -> None:
        from rest_framework.exceptions import PermissionDenied  # noqa: PLC0415

        from apps.organizations.invitations import reissue_initial_owner_invitation  # noqa: PLC0415

        User.objects.filter(pk=platform_admin.pk).update(is_staff=False)
        with pytest.raises(PermissionDenied):
            reissue_initial_owner_invitation(
                actor=platform_admin, organization=created, email="z@example.org"
            )
        with pytest.raises(PermissionDenied):
            reissue_initial_owner_invitation(
                actor=None, organization=created, email="z@example.org"
            )

    def test_no_active_organization_without_an_active_owner(
        self, created: Organization, make_org: Callable[..., Organization]
    ) -> None:
        token = deliver()["head@riverside.example.org"]
        accept(token, new_account_body())
        for organization in Organization.objects.filter(status=OrganizationStatus.ACTIVE):
            if organization.pk != created.pk:
                continue
            owners = MembershipRole.objects.filter(
                organization=organization,
                role__system_key=SystemRole.OWNER,
                membership__status="active",
                membership__user__is_active=True,
            )
            assert owners.exists()
        assert activate_for_tests is not None
