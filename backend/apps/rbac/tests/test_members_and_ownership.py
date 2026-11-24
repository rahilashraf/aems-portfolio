"""Member management API, Owner invariant, self-modification and delegation rules."""

from collections.abc import Callable
from typing import Any

import pytest

from apps.accounts.models import User
from apps.organizations.models import Membership, MembershipStatus
from apps.rbac.models import MembershipRole

from .conftest import Team, audit_rows, custom_role, member, role, url

pytestmark = pytest.mark.django_db


@pytest.fixture
def make_member(team: Team) -> Callable[..., Membership]:
    counter = {"n": 0}

    def _make(*roles: Any, status: str = MembershipStatus.ACTIVE) -> Membership:
        counter["n"] += 1
        user = User.objects.create_user(f"m{counter['n']}@example.org", "x" * 12, full_name="M")
        return member(team.org, user, *roles, status=status)

    return _make


def member_url(team: Team, membership: Membership, suffix: str = "") -> str:
    return url(team.org, f"members/{membership.pk}/{suffix}")


def role_ids(membership: Membership) -> set[Any]:
    return set(
        MembershipRole.objects.filter(membership=membership).values_list("role_id", flat=True)
    )


# ------------------------------------------------------------------------------ read APIs
class TestMemberReads:
    def test_list_is_scoped_ordered_and_shaped(self, team: Team, as_user: Any) -> None:
        body = as_user(team.admin).get(url(team.org, "members/")).json()
        assert body["count"] == 7  # A's memberships only (the B membership of admin excluded)
        emails = {r["user"]["email"] for r in body["results"]}
        assert team.other_owner.email not in emails
        first = body["results"][0]
        assert set(first) == {"id", "user", "status", "joined_at", "roles"}
        assert set(first["user"]) == {"id", "email", "full_name"}
        owner_entry = next(r for r in body["results"] if r["user"]["email"] == team.owner.email)
        assert owner_entry["roles"] == [
            {"id": str(role(team.org, "owner").pk), "name": "Owner", "system_key": "owner"}
        ]

    def test_filters_and_validation(self, team: Team, as_user: Any) -> None:
        client = as_user(team.admin)
        suspended = client.get(url(team.org, "members/"), data={"status": "suspended"}).json()
        assert [r["user"]["email"] for r in suspended["results"]] == [team.suspended.email]
        for params in ({"status": "nope"}, {"ordering": "user__password"}, {"page": "0"}):
            response = client.get(url(team.org, "members/"), data=params)
            assert response.status_code == 400
            assert response.json()["code"] == "invalid_query_parameters"

    def test_foreign_and_unknown_membership_ids_are_404(self, team: Team, as_user: Any) -> None:
        foreign = team.membership(team.other_owner, team.other)
        client = as_user(team.owner)
        for path in (
            f"members/{foreign.pk}/",
            "members/00000000-0000-4000-8000-000000000000/",
            f"members/{foreign.pk}/roles/",
        ):
            for method, body in (
                ("get", None),
                ("patch", {"status": "suspended"}),
                ("delete", None),
                ("put", {"role_ids": []}),
            ):
                if path.endswith("roles/") != (method == "put"):
                    continue
                call = getattr(client, method)
                response = (
                    call(url(team.org, path), body)
                    if body is not None
                    else call(url(team.org, path))
                )
                assert response.status_code == 404, (path, method)
        assert Membership.objects.filter(pk=foreign.pk, status=MembershipStatus.ACTIVE).exists()
        assert as_user(team.owner).get(url(team.org, "members/not-a-uuid/")).status_code == 404


# ------------------------------------------------------------------------ status changes
class TestStatusAndRemoval:
    def test_suspend_and_reactivate(self, team: Team, as_user: Any, make_member: Any) -> None:
        target = make_member(role(team.org, "member"))
        client = as_user(team.admin)
        response = client.patch(member_url(team, target), {"status": "suspended"})
        assert response.status_code == 200
        assert response.json()["status"] == "suspended"
        assert client.patch(member_url(team, target), {"status": "suspended"}).status_code == 200
        assert client.patch(member_url(team, target), {"status": "active"}).status_code == 200
        events = audit_rows("rbac.membership.status_changed")
        assert len(events) == 2  # the repeated suspension changed nothing and recorded nothing
        assert events[0].changes == {"status": {"from": "active", "to": "suspended"}}
        assert events[0].organization_id == team.org.pk
        assert events[0].actor_id == team.admin.pk
        assert events[0].target_type == "membership"
        assert events[0].metadata == {"member_user_id": str(target.user_id)}

    @pytest.mark.parametrize(
        "body",
        [
            {"status": "banned"},
            {},
            {"status": "suspended", "organization": "x"},
            {"status": "suspended", "user": "x"},
            {"status": "suspended", "roles": []},
        ],
    )
    def test_strict_bodies(
        self, team: Team, as_user: Any, make_member: Any, body: dict[str, Any]
    ) -> None:
        target = make_member()
        assert as_user(team.admin).patch(member_url(team, target), body).status_code == 400
        target.refresh_from_db()
        assert target.status == MembershipStatus.ACTIVE

    def test_remove_member(self, team: Team, as_user: Any, make_member: Any) -> None:
        target = make_member(role(team.org, "member"), team.auditors)
        response = as_user(team.owner).delete(member_url(team, target))
        assert response.status_code == 204
        assert not Membership.objects.filter(pk=target.pk).exists()
        assert not MembershipRole.objects.filter(membership_id=target.pk).exists()
        assert User.objects.filter(pk=target.user_id, is_active=True).exists()  # account intact
        [event] = audit_rows("rbac.membership.removed")
        assert event.target_id == str(target.pk)
        assert sorted(event.metadata["roles_removed"]) == sorted(
            [str(role(team.org, "member").pk), str(team.auditors.pk)]
        )

    @pytest.mark.parametrize("action", ["suspend", "remove", "roles"])
    def test_no_self_modification(self, team: Team, as_user: Any, action: str) -> None:
        own = team.membership(team.admin)
        client = as_user(team.admin)
        if action == "suspend":
            response = client.patch(member_url(team, own), {"status": "suspended"})
        elif action == "remove":
            response = client.delete(member_url(team, own))
        else:
            response = client.put(
                member_url(team, own, "roles/"),
                {"role_ids": [str(role(team.org, "admin").pk), str(role(team.org, "owner").pk)]},
            )
        assert response.status_code == 403
        assert response.json()["code"] == "self_modification_not_allowed"
        own.refresh_from_db()
        assert own.status == MembershipStatus.ACTIVE
        assert role_ids(own) == {role(team.org, "admin").pk}

    def test_admins_cannot_act_on_owners(self, team: Team, as_user: Any, make_member: Any) -> None:
        co_owner = make_member(role(team.org, "owner"))
        client = as_user(team.admin)
        for response in (
            client.patch(member_url(team, co_owner), {"status": "suspended"}),
            client.delete(member_url(team, co_owner)),
            client.put(member_url(team, co_owner, "roles/"), {"role_ids": []}),
            client.put(
                member_url(team, co_owner, "roles/"),
                {"role_ids": [str(role(team.org, "owner").pk), str(team.auditors.pk)]},
            ),
        ):
            assert response.status_code == 403
            assert response.json()["code"] == "owner_role_restricted"
        assert role_ids(co_owner) == {role(team.org, "owner").pk}

    def test_cannot_act_on_members_holding_more_permissions(
        self, team: Team, as_user: Any, make_member: Any
    ) -> None:
        limited = custom_role(team.org, "Member managers", "members.manage")
        manager = make_member(limited)
        target = make_member(team.auditors)  # holds audit.view, which the manager lacks
        client = as_user(manager.user)
        for response in (
            client.patch(member_url(team, target), {"status": "suspended"}),
            client.delete(member_url(team, target)),
        ):
            assert response.status_code == 403
            assert response.json()["code"] == "delegation_not_allowed"
        bare = make_member()
        assert client.patch(member_url(team, bare), {"status": "suspended"}).status_code == 200


# ---------------------------------------------------------------------- role assignment
class TestRoleAssignment:
    def test_replace_roles(self, team: Team, as_user: Any, make_member: Any) -> None:
        target = make_member(role(team.org, "member"))
        body = {"role_ids": [str(team.auditors.pk), str(role(team.org, "admin").pk)]}
        response = as_user(team.owner).put(member_url(team, target, "roles/"), body)
        assert response.status_code == 200
        assert {r["name"] for r in response.json()["roles"]} == {"Admin", "Auditors"}
        assert role_ids(target) == {team.auditors.pk, role(team.org, "admin").pk}
        [event] = audit_rows("rbac.membership.roles_replaced")
        assert set(event.metadata["roles_added"]) == set(body["role_ids"])
        assert event.metadata["roles_removed"] == [str(role(team.org, "member").pk)]
        link = MembershipRole.objects.get(membership=target, role=team.auditors)
        assert link.assigned_by_id == team.owner.pk
        # Same set again: no write, no audit record.
        assert as_user(team.owner).put(member_url(team, target, "roles/"), body).status_code == 200
        assert len(audit_rows("rbac.membership.roles_replaced")) == 1

    @pytest.mark.parametrize("kind", ["foreign", "unknown", "malformed", "too_many", "org_key"])
    def test_invalid_role_references(
        self, team: Team, as_user: Any, make_member: Any, kind: str
    ) -> None:
        target = make_member()
        bodies: dict[str, Any] = {
            "foreign": {"role_ids": [str(role(team.other, "admin").pk)]},
            "unknown": {"role_ids": ["00000000-0000-4000-8000-000000000000"]},
            "malformed": {"role_ids": ["admin"]},
            "too_many": {"role_ids": [str(team.auditors.pk)] * 21},
            "org_key": {"role_ids": [], "organization_id": str(team.other.pk)},
        }
        response = as_user(team.owner).put(member_url(team, target, "roles/"), bodies[kind])
        assert response.status_code == 400
        assert role_ids(target) == set()

    def test_only_owners_grant_the_owner_role(
        self, team: Team, as_user: Any, make_member: Any
    ) -> None:
        target = make_member()
        body = {"role_ids": [str(role(team.org, "owner").pk)]}
        response = as_user(team.admin).put(member_url(team, target, "roles/"), body)
        assert response.status_code == 403
        assert response.json()["code"] == "owner_role_restricted"
        # A custom role holding every permission is still not Owner.
        everything = custom_role(
            team.org,
            "Everything",
            "organization.view",
            "organization.update",
            "members.view",
            "members.manage",
            "invitations.manage",
            "roles.view",
            "roles.manage",
            "audit.view",
        )
        almighty = make_member(everything)
        assert (
            as_user(almighty.user).put(member_url(team, target, "roles/"), body).status_code == 403
        )
        assert as_user(team.owner).put(member_url(team, target, "roles/"), body).status_code == 200
        [granted] = audit_rows("rbac.owner.granted")
        assert granted.target_id == str(target.pk)
        assert granted.actor_id == team.owner.pk

    def test_delegation_limits_role_assignment(
        self, team: Team, as_user: Any, make_member: Any
    ) -> None:
        admin_role = role(team.org, "admin")
        admin_role.permissions.remove(*admin_role.permissions.filter(code="audit.view"))
        target = make_member()
        client = as_user(team.admin)
        response = client.put(
            member_url(team, target, "roles/"), {"role_ids": [str(team.auditors.pk)]}
        )
        assert response.status_code == 403
        assert response.json()["code"] == "delegation_not_allowed"
        # Removing a role carrying a permission the actor lacks is refused too.
        grant_target = make_member(team.auditors)
        response = client.put(member_url(team, grant_target, "roles/"), {"role_ids": []})
        assert response.status_code == 403
        assert role_ids(grant_target) == {team.auditors.pk}
        # Roles within the actor's own permissions are fine.
        ok = client.put(
            member_url(team, target, "roles/"), {"role_ids": [str(role(team.org, "member").pk)]}
        )
        assert ok.status_code == 200

    def test_owner_relinquishes_only_with_another_active_owner(
        self, team: Team, as_user: Any, make_member: Any
    ) -> None:
        own = team.membership(team.owner)
        client = as_user(team.owner)
        response = client.put(member_url(team, own, "roles/"), {"role_ids": []})
        assert response.status_code == 409
        assert response.json()["code"] == "last_owner"
        assert role_ids(own) == {role(team.org, "owner").pk}
        # A suspended or deactivated co-Owner does not count.
        make_member(role(team.org, "owner"), status=MembershipStatus.SUSPENDED)
        inactive = make_member(role(team.org, "owner"))
        User.objects.filter(pk=inactive.user_id).update(is_active=False)
        assert client.put(member_url(team, own, "roles/"), {"role_ids": []}).status_code == 409
        make_member(role(team.org, "owner"))
        response = client.put(member_url(team, own, "roles/"), {"role_ids": []})
        assert response.status_code == 200
        assert role_ids(own) == set()
        [event] = audit_rows("rbac.owner.relinquished")
        assert event.actor_id == team.owner.pk
        assert not audit_rows("rbac.owner.revoked")

    def test_relinquishing_cannot_be_combined_with_other_changes(
        self, team: Team, as_user: Any, make_member: Any
    ) -> None:
        make_member(role(team.org, "owner"))
        own = team.membership(team.owner)
        grant_admin = {"role_ids": [str(role(team.org, "admin").pk)]}
        response = as_user(team.owner).put(member_url(team, own, "roles/"), grant_admin)
        assert response.status_code == 403
        assert response.json()["code"] == "self_modification_not_allowed"
        assert role_ids(own) == {role(team.org, "owner").pk}

    def test_owner_revokes_another_owner(self, team: Team, as_user: Any, make_member: Any) -> None:
        co_owner = make_member(role(team.org, "owner"))
        response = as_user(team.owner).put(member_url(team, co_owner, "roles/"), {"role_ids": []})
        assert response.status_code == 200
        [event] = audit_rows("rbac.owner.revoked")
        assert event.target_id == str(co_owner.pk)

    def test_owners_can_suspend_and_remove_co_owners(
        self, team: Team, as_user: Any, make_member: Any
    ) -> None:
        first, second = make_member(role(team.org, "owner")), make_member(role(team.org, "owner"))
        client = as_user(team.owner)
        assert client.patch(member_url(team, first), {"status": "suspended"}).status_code == 200
        assert client.delete(member_url(team, second)).status_code == 204


# --------------------------------------------------------------------- last-Owner guard
class TestLastOwnerGuard:
    """Direct service calls for states the API cannot reach (the acting Owner always remains)."""

    def test_suspension_and_removal_refuse_to_drop_the_last_owner(
        self, team: Team, make_member: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from apps.rbac import services  # noqa: PLC0415
        from apps.rbac.exceptions import LastOwnerError  # noqa: PLC0415

        target = team.membership(team.owner)
        # A second Owner acts, then pretend it does not count (e.g. its account was just
        # deactivated in another transaction): the target is then the last active Owner.
        actor = make_member(role(team.org, "owner"))
        real = services._active_owner_ids
        monkeypatch.setattr(services, "_active_owner_ids", lambda org: real(org) - {actor.pk})
        with pytest.raises(LastOwnerError) as exc:
            services.update_membership_status(
                actor=actor.user,
                organization=team.org,
                membership_id=target.pk,
                status=MembershipStatus.SUSPENDED,
            )
        assert exc.value.organization_ids == (str(team.org.pk),)
        with pytest.raises(LastOwnerError):
            services.remove_membership(
                actor=actor.user, organization=team.org, membership_id=target.pk
            )
        with pytest.raises(LastOwnerError):
            services.replace_membership_roles(
                actor=actor.user, organization=team.org, membership_id=target.pk, role_ids=[]
            )
        target.refresh_from_db()
        assert target.status == MembershipStatus.ACTIVE
        assert role_ids(target) == {role(team.org, "owner").pk}
        assert not audit_rows("rbac.membership.status_changed")

    def test_service_input_validation(self, team: Team) -> None:
        from apps.rbac import services  # noqa: PLC0415
        from apps.rbac.exceptions import RbacForbiddenError  # noqa: PLC0415

        with pytest.raises(ValueError, match="status"):
            services.update_membership_status(
                actor=team.owner, organization=team.org, membership_id=None, status="banned"
            )
        with pytest.raises(RbacForbiddenError):  # not a member of the organization at all
            services.remove_membership(
                actor=team.outsider,
                organization=team.org,
                membership_id=team.membership(team.member).pk,
            )
        with pytest.raises(RbacForbiddenError):  # member without any permission
            services.remove_membership(
                actor=team.norole,
                organization=team.org,
                membership_id=team.membership(team.member).pk,
            )
