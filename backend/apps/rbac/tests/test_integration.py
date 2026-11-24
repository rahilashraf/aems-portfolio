"""Deactivation, organization profile and /me/, audit atomicity and redaction for RBAC."""

from collections.abc import Callable
from typing import Any

import pytest
from django.contrib import admin
from django.db import DatabaseError
from django.test import Client

from apps.accounts.models import AuthSession, User
from apps.accounts.services import deactivate_user
from apps.accounts.tests.conftest import PASSWORD, do_login
from apps.audit.models import AuditLog
from apps.organizations.models import Membership, MembershipStatus, Organization
from apps.organizations.services import update_organization_profile
from apps.rbac import services
from apps.rbac.exceptions import LastOwnerError, RbacForbiddenError
from apps.rbac.models import MembershipRole, Role

from .conftest import Team, audit_rows, custom_role, member, role, url

pytestmark = pytest.mark.django_db


# ------------------------------------------------------------------ global deactivation
class TestDeactivation:
    def test_last_owner_cannot_be_deactivated_and_nothing_changes(self, team: Team) -> None:
        do_login(team.owner.email)
        with pytest.raises(LastOwnerError) as exc:
            deactivate_user(team.owner, actor=team.platform_admin)
        assert exc.value.organization_ids == (str(team.org.pk),)
        team.owner.refresh_from_db()
        assert team.owner.is_active
        assert AuthSession.objects.filter(user=team.owner, revoked_at__isnull=True).exists()
        assert not audit_rows("auth.account.deactivated")

    def test_every_blocking_organization_is_listed(self, team: Team) -> None:
        # Sole Owner of B as well; co-Owner in a third organization does not block.
        member(team.other, team.owner, role(team.other, "owner"))
        Membership.objects.filter(user=team.other_owner, organization=team.other).delete()
        third = Organization.objects.create(
            name="Third", slug="third", organization_type="other", created_by=team.platform_admin
        )
        Organization.objects.filter(pk=third.pk).update(status="active")
        services.seed_system_roles(third)
        member(third, team.owner, role(third, "owner"))
        member(third, team.member, role(third, "owner"))
        with pytest.raises(LastOwnerError) as exc:
            deactivate_user(team.owner)
        assert exc.value.organization_ids == tuple(sorted([str(team.org.pk), str(team.other.pk)]))
        assert User.objects.get(pk=team.owner.pk).is_active  # one failure rolls back everything

    def test_deactivation_with_a_remaining_owner(self, team: Team) -> None:
        member(
            team.org,
            User.objects.create_user("co@example.org", PASSWORD, full_name="C"),
            role(team.org, "owner"),
        )
        do_login(team.owner.email)
        assert deactivate_user(team.owner, actor=team.platform_admin) == 1
        assert not User.objects.get(pk=team.owner.pk).is_active
        [event] = audit_rows("auth.account.deactivated")
        assert event.target_id == str(team.owner.pk)
        assert audit_rows("auth.session.revoked") or audit_rows("auth.sessions.revoked")

    def test_inactive_co_owner_and_non_active_organizations(self, team: Team) -> None:
        # A suspended or provisioning organization does not need an Owner.
        Organization.objects.filter(pk=team.org.pk).update(status="suspended")
        assert deactivate_user(team.owner) == 0
        # Deactivating an already inactive account is a no-op for ownership.
        assert deactivate_user(team.inactive) == 0

    def test_staff_admin_form_reports_the_blocking_organizations(self, team: Team) -> None:
        superuser = team.superuser
        client = Client()
        client.force_login(superuser)
        response = client.post(
            f"/admin/accounts/user/{team.owner.pk}/change/",
            {"email": team.owner.email, "full_name": team.owner.full_name},  # is_active unchecked
        )
        assert response.status_code == 200  # form re-rendered with the error
        assert str(team.org.pk) in response.content.decode()
        assert User.objects.get(pk=team.owner.pk).is_active
        assert admin.site.is_registered(Role)


# ------------------------------------------------------------- organization profile, /me/
class TestOrganizationEndpoints:
    def test_profile_update_requires_and_rechecks_organization_update(
        self, team: Team, as_user: Any
    ) -> None:
        response = as_user(team.admin).patch(url(team.org), {"name": "Acme Renamed"})
        assert response.status_code == 200
        assert response.json()["name"] == "Acme Renamed"
        [event] = audit_rows("organization.profile_updated")
        assert event.actor_id == team.admin.pk
        assert as_user(team.member).patch(url(team.org), {"name": "X"}).status_code == 403
        for body in ({"slug": "new-slug"}, {"status": "suspended"}, {"organization_type": "other"}):
            assert as_user(team.owner).patch(url(team.org), body).status_code == 400
        team.org.refresh_from_db()
        assert (team.org.slug, team.org.status) == ("acme", "active")
        # The service re-checks under the lock (stale request-level authorization).
        with pytest.raises(RbacForbiddenError):
            update_organization_profile(
                actor=team.member, organization=team.org, changes={"name": "Nope"}
            )

    def test_me_returns_roles_and_effective_permissions(self, team: Team, as_user: Any) -> None:
        body = as_user(team.auditor).get(url(team.org, "me/")).json()
        assert set(body) == {"organization", "membership", "roles", "permissions"}
        assert body["roles"] == [
            {"id": str(team.auditors.pk), "name": "Auditors", "system_key": None}
        ]
        assert body["permissions"] == ["audit.view"]
        assert body["membership"]["id"] == str(team.membership(team.auditor).pk)
        owner = as_user(team.owner).get(url(team.org, "me/")).json()
        assert owner["roles"][0]["system_key"] == "owner"
        assert len(owner["permissions"]) == 8
        assert as_user(team.norole).get(url(team.org, "me/")).json()["permissions"] == []
        # Multi-organization user: different roles in each organization.
        assert as_user(team.admin).get(url(team.other, "me/")).json()["permissions"] == [
            "organization.view"
        ]


# ---------------------------------------------------------------------- audit atomicity
def _fail_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    def failing_save(*_args: Any, **_kwargs: Any) -> None:
        raise DatabaseError("audit storage unavailable")

    monkeypatch.setattr(AuditLog, "save", failing_save)


class TestAuditAtomicity:
    @pytest.mark.parametrize(
        "operation",
        ["create_role", "update_role", "delete_role", "status", "remove", "roles", "profile"],
    )
    def test_audit_failure_rolls_back_the_mutation(
        self, team: Team, monkeypatch: pytest.MonkeyPatch, operation: str
    ) -> None:
        spare = custom_role(team.org, "Spare", "members.view")
        target = team.membership(team.member)
        snapshot = {
            "roles": sorted(Role.objects.values_list("pk", "name")),
            "links": sorted(MembershipRole.objects.values_list("membership_id", "role_id")),
            "members": sorted(Membership.objects.values_list("pk", "status")),
            "org": Organization.objects.get(pk=team.org.pk).name,
            "spare": sorted(spare.permissions.values_list("code", flat=True)),
        }
        calls: dict[str, Callable[[], Any]] = {
            "create_role": lambda: services.create_role(
                actor=team.owner, organization=team.org, name="New"
            ),
            "update_role": lambda: services.update_role(
                actor=team.owner,
                organization=team.org,
                role_id=spare.pk,
                changes={"name": "Renamed", "permissions": ["audit.view"]},
            ),
            "delete_role": lambda: services.delete_role(
                actor=team.owner, organization=team.org, role_id=spare.pk
            ),
            "status": lambda: services.update_membership_status(
                actor=team.owner, organization=team.org, membership_id=target.pk, status="suspended"
            ),
            "remove": lambda: services.remove_membership(
                actor=team.owner, organization=team.org, membership_id=target.pk
            ),
            "roles": lambda: services.replace_membership_roles(
                actor=team.owner,
                organization=team.org,
                membership_id=target.pk,
                role_ids=[role(team.org, "owner").pk],
            ),
            "profile": lambda: update_organization_profile(
                actor=team.owner, organization=team.org, changes={"name": "Changed"}
            ),
        }
        before = AuditLog.objects.count()
        _fail_audit(monkeypatch)
        with pytest.raises(DatabaseError, match="audit storage"):
            calls[operation]()
        monkeypatch.undo()
        assert snapshot == {
            "roles": sorted(Role.objects.values_list("pk", "name")),
            "links": sorted(MembershipRole.objects.values_list("membership_id", "role_id")),
            "members": sorted(Membership.objects.values_list("pk", "status")),
            "org": Organization.objects.get(pk=team.org.pk).name,
            "spare": sorted(spare.permissions.values_list("code", flat=True)),
        }
        assert AuditLog.objects.count() == before

    def test_deactivation_audit_failure_rolls_back(
        self, team: Team, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        member(
            team.org,
            User.objects.create_user("co@example.org", PASSWORD, full_name="C"),
            role(team.org, "owner"),
        )
        _fail_audit(monkeypatch)
        with pytest.raises(DatabaseError):
            deactivate_user(team.owner)
        monkeypatch.undo()
        assert User.objects.get(pk=team.owner.pk).is_active

    def test_api_mutations_record_exactly_one_event_each_and_no_secrets(
        self, team: Team, as_user: Any
    ) -> None:
        client = as_user(team.owner)
        target = team.membership(team.member)
        created = client.post(
            url(team.org, "roles/"), {"name": "Ops", "permissions": ["members.view"]}
        ).json()
        client.patch(url(team.org, f"roles/{created['id']}/"), {"description": "Operators"})
        client.put(url(team.org, f"members/{target.pk}/roles/"), {"role_ids": [created["id"]]})
        client.patch(url(team.org, f"members/{target.pk}/"), {"status": "suspended"})
        client.delete(url(team.org, f"members/{target.pk}/"))
        client.delete(url(team.org, f"roles/{created['id']}/"))
        actions = list(
            AuditLog.objects.filter(action__startswith="rbac.")
            .order_by("created_at", "id")
            .values_list("action", flat=True)
        )
        assert actions == [
            "rbac.role.created",
            "rbac.role.updated",
            "rbac.membership.roles_replaced",
            "rbac.membership.status_changed",
            "rbac.membership.removed",
            "rbac.role.deleted",
        ]
        rows = AuditLog.objects.filter(action__startswith="rbac.")
        assert {r.organization_id for r in rows} == {team.org.pk}
        assert {r.actor_id for r in rows} == {team.owner.pk}
        text = " ".join(str(v) for r in rows.values() for v in r.values())
        assert PASSWORD not in text
        assert "Bearer" not in text
        assert "password" not in text.lower()

    def test_audit_history_of_one_organization_excludes_the_other(
        self, team: Team, as_user: Any
    ) -> None:
        as_user(team.owner).post(url(team.org, "roles/"), {"name": "Only A"})
        as_user(team.other_owner).post(url(team.other, "roles/"), {"name": "Only B"})
        body = as_user(team.owner).get(url(team.org, "audit-logs/")).json()
        created = [r for r in body["results"] if r["action"] == "rbac.role.created"]
        assert [r["changes"]["name"]["to"] for r in created] == ["Only A"]

    def test_membership_status_values(self, team: Team) -> None:
        assert MembershipStatus.values == ["active", "suspended"]


class TestServiceEdges:
    def test_service_level_validation(self, team: Team, monkeypatch: pytest.MonkeyPatch) -> None:
        from django.db import IntegrityError  # noqa: PLC0415

        from apps.rbac.exceptions import UnknownPermissionError  # noqa: PLC0415

        with pytest.raises(UnknownPermissionError):
            services.create_role(
                actor=team.owner, organization=team.org, name="X", permissions=["nope.nope"]
            )
        with pytest.raises(ValueError, match="system_key"):
            services.update_role(
                actor=team.owner,
                organization=team.org,
                role_id=team.auditors.pk,
                changes={"system_key": "owner"},
            )

        def other_violation(*_args: Any, **_kwargs: Any) -> None:
            raise IntegrityError("another constraint")

        monkeypatch.setattr(Role, "save", other_violation)
        with pytest.raises(IntegrityError, match="another constraint"):
            services.create_role(actor=team.owner, organization=team.org, name="Y")

    def test_unchanged_profile_records_nothing(self, team: Team) -> None:
        update_organization_profile(
            actor=team.owner, organization=team.org, changes={"name": team.org.name}
        )
        assert not audit_rows("organization.profile_updated")
