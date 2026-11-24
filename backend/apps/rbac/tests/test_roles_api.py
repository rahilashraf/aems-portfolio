"""Role management API: CRUD, system-role protection, delegation and shared-role escalation."""

from typing import Any

import pytest

from apps.accounts.models import User
from apps.rbac.models import Role

from .conftest import Team, audit_rows, custom_role, member, role, url
from .test_registry_and_models import PHASE_1_CATALOG

pytestmark = pytest.mark.django_db


def role_url(team: Team, r: Role) -> str:
    return url(team.org, f"roles/{r.pk}/")


def codes(r: Role) -> set[str]:
    return set(r.permissions.values_list("code", flat=True))


class TestReads:
    def test_list_detail_and_catalog(self, team: Team, as_user: Any) -> None:
        client = as_user(team.admin)
        body = client.get(url(team.org, "roles/")).json()
        assert [r["name"] for r in body["results"]] == ["Admin", "Auditors", "Member", "Owner"]
        owner = next(r for r in body["results"] if r["system_key"] == "owner")
        assert set(owner["permissions"]) == PHASE_1_CATALOG  # dynamic, not stored
        assert set(owner) == {
            "id",
            "name",
            "description",
            "is_system",
            "system_key",
            "permissions",
            "created_at",
            "updated_at",
        }
        assert client.get(url(team.org, "roles/"), data={"is_system": "false"}).json()["count"] == 1
        detail = client.get(role_url(team, team.auditors)).json()
        assert detail["permissions"] == ["audit.view"]
        catalog = client.get(url(team.org, "permissions/")).json()
        assert [p["code"] for p in catalog["results"]] == sorted(PHASE_1_CATALOG)
        assert set(catalog["results"][0]) == {"code", "description", "category"}

    def test_roles_of_other_organizations_are_404(self, team: Team, as_user: Any) -> None:
        foreign = role(team.other, "admin")
        client = as_user(team.owner)
        assert client.get(url(team.org, f"roles/{foreign.pk}/")).status_code == 404
        assert client.patch(url(team.org, f"roles/{foreign.pk}/"), {"name": "X"}).status_code == 404
        assert client.delete(url(team.org, f"roles/{foreign.pk}/")).status_code == 404
        assert Role.objects.filter(pk=foreign.pk, name="Admin").exists()

    def test_deprecated_permissions_are_not_listed_or_granted(
        self, team: Team, as_user: Any
    ) -> None:
        from apps.rbac.models import Permission  # noqa: PLC0415

        Permission.objects.filter(code="invitations.manage").update(is_deprecated=True)
        catalog = as_user(team.owner).get(url(team.org, "permissions/")).json()
        assert "invitations.manage" not in {p["code"] for p in catalog["results"]}


class TestCreate:
    def test_create_custom_role(self, team: Team, as_user: Any) -> None:
        body = {"name": "  Reviewers ", "description": "Reads", "permissions": ["members.view"]}
        response = as_user(team.admin).post(url(team.org, "roles/"), body)
        assert response.status_code == 201
        data = response.json()
        assert (data["name"], data["is_system"], data["system_key"]) == ("Reviewers", False, None)
        assert data["permissions"] == ["members.view"]
        [event] = audit_rows("rbac.role.created")
        assert event.changes == {"name": {"from": None, "to": "Reviewers"}}
        assert event.metadata == {"permissions_added": ["members.view"]}
        assert event.organization_id == team.org.pk

    @pytest.mark.parametrize(
        ("body", "status", "code"),
        [
            ({"name": "auditors"}, 409, "role_name_taken"),
            ({"name": "OWNER"}, 409, "role_name_taken"),
            ({"name": "X", "permissions": ["audit.export"]}, 400, "validation_error"),
            ({"name": "X", "system_key": "owner"}, 400, "validation_error"),
            ({"name": "X", "is_system": True}, 400, "validation_error"),
            ({"name": "X", "organization": "x"}, 400, "validation_error"),
            ({"name": ""}, 400, "validation_error"),
            ({"name": "x" * 101}, 400, "validation_error"),
        ],
    )
    def test_invalid_creation(
        self, team: Team, as_user: Any, body: dict[str, Any], status: int, code: str
    ) -> None:
        before = Role.objects.count()
        response = as_user(team.owner).post(url(team.org, "roles/"), body)
        assert response.status_code == status, response.content
        assert response.json()["code"] == code
        assert Role.objects.count() == before
        assert not audit_rows("rbac.role.created")

    def test_cannot_create_a_role_with_permissions_you_lack(self, team: Team, as_user: Any) -> None:
        managers = custom_role(team.org, "Role managers", "roles.manage", "roles.view")
        actor = member(
            team.org, User.objects.create_user("rm@example.org", "x" * 12, full_name="R"), managers
        )
        client = as_user(actor.user)
        response = client.post(
            url(team.org, "roles/"), {"name": "Up", "permissions": ["audit.view"]}
        )
        assert response.status_code == 403
        assert response.json()["code"] == "delegation_not_allowed"
        ok = client.post(url(team.org, "roles/"), {"name": "Same", "permissions": ["roles.view"]})
        assert ok.status_code == 201


class TestUpdate:
    def test_rename_and_change_permissions(self, team: Team, as_user: Any) -> None:
        body = {"name": "Auditing", "permissions": ["audit.view", "members.view"]}
        response = as_user(team.admin).patch(role_url(team, team.auditors), body)
        assert response.status_code == 200
        assert response.json()["permissions"] == ["audit.view", "members.view"]
        [updated] = audit_rows("rbac.role.updated")
        assert updated.changes == {"name": {"from": "Auditors", "to": "Auditing"}}
        [changed] = audit_rows("rbac.role.permissions_changed")
        assert changed.metadata == {
            "permissions_added": ["members.view"],
            "permissions_removed": [],
        }
        # A no-op records nothing.
        assert as_user(team.admin).patch(role_url(team, team.auditors), body).status_code == 200
        assert len(audit_rows("rbac.role.updated")) == 1

    def test_owner_role_is_immutable(self, team: Team, as_user: Any) -> None:
        owner_role = role(team.org, "owner")
        for body in ({"name": "Boss"}, {"description": "x"}, {"permissions": ["audit.view"]}):
            response = as_user(team.owner).patch(role_url(team, owner_role), body)
            assert response.status_code == 409
            assert response.json()["code"] == "system_role_protected"
        assert as_user(team.owner).delete(role_url(team, owner_role)).status_code == 409
        owner_role.refresh_from_db()
        assert (owner_role.name, codes(owner_role)) == ("Owner", set())

    def test_admin_and_member_permissions_are_editable_names_are_not(
        self, team: Team, as_user: Any
    ) -> None:
        member_role = role(team.org, "member")
        client = as_user(team.owner)
        response = client.patch(
            role_url(team, member_role), {"permissions": ["organization.view", "members.view"]}
        )
        assert response.status_code == 200
        assert codes(member_role) == {"organization.view", "members.view"}
        for body in ({"name": "Staff"}, {"description": "Changed"}):
            assert client.patch(role_url(team, member_role), body).status_code == 409
        for system in ("admin", "member"):
            assert client.delete(role_url(team, role(team.org, system))).status_code == 409

    def test_delegation_on_role_edits(self, team: Team, as_user: Any) -> None:
        managers = custom_role(team.org, "Role managers", "roles.manage", "members.view")
        actor = member(
            team.org, User.objects.create_user("rm@example.org", "x" * 12, full_name="R"), managers
        )
        client = as_user(actor.user)
        # Cannot add a permission it lacks, nor remove one it lacks.
        response = client.patch(
            role_url(team, team.auditors), {"permissions": ["audit.view", "roles.view"]}
        )
        assert response.status_code == 403
        assert response.json()["code"] == "delegation_not_allowed"
        response = client.patch(role_url(team, team.auditors), {"permissions": []})
        assert response.status_code == 403
        assert codes(team.auditors) == {"audit.view"}

    def test_shared_role_cannot_raise_the_editors_own_permissions(
        self, team: Team, as_user: Any
    ) -> None:
        """The actor holds the role it edits (shared with others): no self-escalation."""
        shared = custom_role(team.org, "Shared", "roles.manage", "roles.view")
        actor = member(
            team.org, User.objects.create_user("s1@example.org", "x" * 12, full_name="S"), shared
        )
        peer = member(
            team.org, User.objects.create_user("s2@example.org", "x" * 12, full_name="S"), shared
        )
        client = as_user(actor.user)
        for added in ("members.manage", "audit.view", "organization.update"):
            response = client.patch(
                role_url(team, shared), {"permissions": ["roles.manage", "roles.view", added]}
            )
            assert response.status_code == 403, added
        assert codes(shared) == {"roles.manage", "roles.view"}
        # Nor through a second role: assigning needs members.manage, which it does not hold.
        response = client.put(
            url(team.org, f"members/{actor.pk}/roles/"),
            {"role_ids": [str(role(team.org, "admin").pk)]},
        )
        assert response.status_code == 403
        assert peer.status == "active"
        # Self-demotion through the shared role is allowed (it holds what it removes).
        assert (
            client.patch(role_url(team, shared), {"permissions": ["roles.manage"]}).status_code
            == 200
        )

    def test_admin_cannot_turn_a_role_into_owner(self, team: Team, as_user: Any) -> None:
        for body in ({"system_key": "owner"}, {"is_system": True}, {"organization": "x"}):
            assert as_user(team.owner).patch(role_url(team, team.auditors), body).status_code == 400
        team.auditors.refresh_from_db()
        assert (team.auditors.system_key, team.auditors.is_system) == (None, False)


class TestDelete:
    def test_delete_unassigned_custom_role(self, team: Team, as_user: Any) -> None:
        spare = custom_role(team.org, "Spare", "members.view")
        response = as_user(team.admin).delete(role_url(team, spare))
        assert response.status_code == 204
        assert not Role.objects.filter(pk=spare.pk).exists()
        [event] = audit_rows("rbac.role.deleted")
        assert event.target_id == str(spare.pk)
        assert event.changes == {"name": {"from": "Spare", "to": None}}
        assert event.metadata == {"permissions_removed": ["members.view"]}

    def test_assigned_roles_cannot_be_deleted(self, team: Team, as_user: Any) -> None:
        response = as_user(team.owner).delete(role_url(team, team.auditors))
        assert response.status_code == 409
        assert response.json()["code"] == "role_in_use"
        assert Role.objects.filter(pk=team.auditors.pk).exists()
