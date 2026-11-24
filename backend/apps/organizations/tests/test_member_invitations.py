"""Member invitations to an active organization: creation, listing, revocation, preview and
acceptance, with delegation re-validation and tenant isolation (ADR-0018)."""

from datetime import timedelta
from typing import Any

import pytest
from django.core import mail
from django.test import Client

from apps.accounts.models import User
from apps.audit.models import AuditLog
from apps.organizations import invitations
from apps.organizations.models import (
    Invitation,
    InvitationStatus,
    Membership,
    Organization,
    OrganizationStatus,
)
from apps.organizations.tests.conftest import Api
from apps.rbac.models import MembershipRole
from apps.rbac.tests.conftest import Team, custom_role, member, role

from .invitation_helpers import (
    NEW_PASSWORD,
    accept,
    deliver,
    new_account_body,
    preview,
)

pytestmark = pytest.mark.django_db
NEWCOMER = "newcomer@example.org"


def invitations_url(target: Team | Organization, suffix: str = "") -> str:
    organization = target.org if isinstance(target, Team) else target
    return f"/api/v1/organizations/{organization.pk}/invitations/{suffix}"


def invite(
    client: Api,
    target: Team | Organization,
    *roles: Any,
    email: str = NEWCOMER,
    expect: int = 201,
) -> dict[str, Any]:
    response = client.post(
        invitations_url(target), {"email": email, "role_ids": [str(r.pk) for r in roles]}
    )
    assert response.status_code == expect, response.content
    body: dict[str, Any] = response.json()
    return body


def audit_actions(organization: Organization) -> list[str]:
    return list(
        AuditLog.objects.filter(organization=organization)
        .order_by("created_at", "id")
        .values_list("action", flat=True)
    )


# ------------------------------------------------------------------------------- creation
class TestCreation:
    def test_admin_invites_with_delegable_roles(self, team: Team, as_user: Any) -> None:
        body = invite(as_user(team.admin), team, role(team.org, "member"), team.auditors)
        assert body["email"] == NEWCOMER
        assert body["status"] == "pending"
        assert body["delivery_status"] == "pending"
        assert body["invited_by"] == str(team.admin.pk)
        assert {r["name"] for r in body["roles"]} == {"Member", "Auditors"}
        assert not {"token", "token_hash"} & set(body)
        assert "invitation.created" in audit_actions(team.org)
        assert mail.outbox == []

    @pytest.mark.parametrize("caller", ["member", "auditor", "norole"])
    def test_requires_invitations_manage(self, team: Team, as_user: Any, caller: str) -> None:
        response = as_user(getattr(team, caller)).post(
            invitations_url(team), {"email": NEWCOMER, "role_ids": [str(team.auditors.pk)]}
        )
        assert response.status_code == 403
        assert not Invitation.objects.exists()

    def test_only_owners_invite_owners(self, team: Team, as_user: Any) -> None:
        response = as_user(team.admin).post(
            invitations_url(team),
            {"email": NEWCOMER, "role_ids": [str(role(team.org, "owner").pk)]},
        )
        assert response.status_code == 403
        assert response.json()["code"] == "owner_role_restricted"
        invite(as_user(team.owner), team, role(team.org, "owner"))

    def test_delegation_applies(self, team: Team, as_user: Any) -> None:
        inviter = member(
            team.org,
            User.objects.create_user("inv@example.org", "x" * 12, full_name="I"),
            custom_role(team.org, "Inviters", "invitations.manage", "organization.view"),
        )
        response = as_user(inviter.user).post(
            invitations_url(team), {"email": NEWCOMER, "role_ids": [str(team.auditors.pk)]}
        )
        assert response.status_code == 403
        assert response.json()["code"] == "delegation_not_allowed"
        invite(as_user(inviter.user), team, role(team.org, "member"))

    @pytest.mark.parametrize(
        ("body", "field"),
        [
            ({"email": "not-an-email", "role_ids": ["{member}"]}, "email"),
            ({"email": NEWCOMER, "role_ids": []}, "role_ids"),
            ({"email": NEWCOMER, "role_ids": ["00000000-0000-4000-8000-000000000000"]}, "role_ids"),
            ({"email": NEWCOMER, "role_ids": ["{foreign}"]}, "role_ids"),
            ({"email": NEWCOMER, "role_ids": ["{member}"], "organization": "x"}, "organization"),
            ({"email": NEWCOMER, "role_ids": ["{member}"], "status": "accepted"}, "status"),
            ({"email": NEWCOMER, "role_ids": ["{member}"], "token": "x" * 43}, "token"),
        ],
    )
    def test_invalid_requests(
        self, team: Team, as_user: Any, body: dict[str, Any], field: str
    ) -> None:
        replacements = {
            "{member}": str(role(team.org, "member").pk),
            "{foreign}": str(role(team.other, "member").pk),
        }
        body = {
            k: [replacements.get(v, v) for v in val] if isinstance(val, list) else val
            for k, val in body.items()
        }
        response = as_user(team.owner).post(invitations_url(team), body)
        assert response.status_code == 400, response.content
        assert field in str(response.json())
        assert not Invitation.objects.exists()

    def test_existing_members_and_duplicates(self, team: Team, as_user: Any) -> None:
        client = as_user(team.owner)
        response = client.post(
            invitations_url(team),
            {"email": team.member.email.upper(), "role_ids": [str(team.auditors.pk)]},
        )
        assert response.status_code == 409
        assert response.json()["code"] == "already_member"
        invite(client, team, team.auditors)
        again = client.post(
            invitations_url(team), {"email": NEWCOMER, "role_ids": [str(team.auditors.pk)]}
        )
        assert again.status_code == 409
        assert again.json()["code"] == "invitation_already_pending"

    def test_expired_pending_invitation_is_replaced(
        self, team: Team, as_user: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first = invite(as_user(team.owner), team, team.auditors)
        later = invitations.now() + timedelta(days=8)
        monkeypatch.setattr(invitations, "now", lambda: later)
        listed = as_user(team.owner).get(invitations_url(team)).json()["results"]
        assert listed[0]["status"] == "expired"
        second = invite(as_user(team.owner), team, team.auditors)
        assert second["id"] != first["id"]
        assert Invitation.objects.get(pk=first["id"]).status == InvitationStatus.EXPIRED
        assert "invitation.expired" in audit_actions(team.org)

    def test_existing_users_of_other_organizations_can_be_invited(
        self, team: Team, as_user: Any
    ) -> None:
        invite(as_user(team.owner), team, team.auditors, email=team.other_owner.email)


# ---------------------------------------------------------------- listing and isolation
class TestListingAndRevocation:
    def test_list_is_scoped_filtered_and_safe(self, team: Team, as_user: Any) -> None:
        invite(as_user(team.owner), team, team.auditors)
        invite(
            as_user(team.other_owner),
            team.other,
            role(team.other, "member"),
            email="b@example.org",
        )
        body = as_user(team.admin).get(invitations_url(team)).json()
        assert [r["email"] for r in body["results"]] == [NEWCOMER]
        text = str(body)
        for invitation in Invitation.objects.all():
            assert invitation.token_hash is None or invitation.token_hash not in text
        invalid = as_user(team.admin).get(invitations_url(team), data={"status": "x"})
        assert invalid.status_code == 400
        filtered = as_user(team.admin).get(invitations_url(team), data={"status": "revoked"})
        assert filtered.json()["count"] == 0
        assert as_user(team.member).get(invitations_url(team)).status_code == 403

    def test_revoke(self, team: Team, as_user: Any) -> None:
        created = invite(as_user(team.owner), team, team.auditors)
        token = deliver()[NEWCOMER]
        response = as_user(team.admin).post(invitations_url(team, f"{created['id']}/revoke/"))
        assert response.status_code == 200
        assert response.json()["status"] == "revoked"
        assert preview(token).status_code == 404
        assert accept(token, new_account_body()).status_code == 404
        again = as_user(team.admin).post(invitations_url(team, f"{created['id']}/revoke/"))
        assert again.status_code == 409
        assert again.json()["code"] == "invitation_not_pending"
        assert "invitation.revoked" in audit_actions(team.org)

    def test_revocation_rules(self, team: Team, as_user: Any) -> None:
        owner_invite = invite(as_user(team.owner), team, role(team.org, "owner"))
        response = as_user(team.admin).post(invitations_url(team, f"{owner_invite['id']}/revoke/"))
        assert response.status_code == 403
        assert response.json()["code"] == "owner_role_restricted"
        assert (
            as_user(team.member)
            .post(invitations_url(team, f"{owner_invite['id']}/revoke/"))
            .status_code
            == 403
        )
        foreign = invite(
            as_user(team.other_owner),
            team.other,
            role(team.other, "member"),
            email="b@example.org",
        )
        assert (
            as_user(team.owner).post(invitations_url(team, f"{foreign['id']}/revoke/")).status_code
            == 404
        )
        assert Invitation.objects.get(pk=foreign["id"]).status == InvitationStatus.PENDING

    def test_accepted_invitation_cannot_be_revoked(self, team: Team, as_user: Any) -> None:
        created = invite(as_user(team.owner), team, team.auditors)
        assert accept(deliver()[NEWCOMER], new_account_body()).status_code == 200
        response = as_user(team.owner).post(invitations_url(team, f"{created['id']}/revoke/"))
        assert response.status_code == 409
        assert Membership.objects.filter(organization=team.org, user__email=NEWCOMER).exists()


# ----------------------------------------------------------------- preview and accept
class TestPreviewAndAcceptance:
    def test_preview(self, team: Team, as_user: Any) -> None:
        invite(as_user(team.owner), team, team.auditors)
        token = deliver()[NEWCOMER]
        response = preview(token)
        assert response.status_code == 200
        assert response.json() == {
            "organization_name": team.org.name,
            "email": "n*******@example.org",
            "status": "pending",
            "expires_at": response.json()["expires_at"],
            "next_step": "sign_in_or_create_account",
        }
        assert response["Cache-Control"] == "no-store, private"
        assert response["Referrer-Policy"] == "no-referrer"
        assert token not in response.content.decode()

    def test_preview_does_not_reveal_whether_an_account_exists(
        self, team: Team, as_user: Any
    ) -> None:
        invite(as_user(team.owner), team, team.auditors, email=team.other_owner.email)
        invite(as_user(team.owner), team, team.auditors, email="nobody@example.org")
        tokens = deliver()
        existing = preview(tokens[team.other_owner.email]).json()
        missing = preview(tokens["nobody@example.org"]).json()
        assert existing["next_step"] == missing["next_step"] == "sign_in_or_create_account"
        signed_in = preview(tokens[team.other_owner.email], user=team.other_owner).json()
        assert signed_in["next_step"] == "accept"

    @pytest.mark.parametrize("state", ["unknown", "malformed", "expired", "revoked", "accepted"])
    def test_unusable_tokens_are_indistinguishable(
        self, team: Team, as_user: Any, state: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        created = invite(as_user(team.owner), team, team.auditors)
        token = deliver()[NEWCOMER]
        if state == "unknown":
            token = "A" * 43
        elif state == "malformed":
            token = "short"
        elif state == "expired":
            later = invitations.now() + timedelta(days=7, seconds=1)
            monkeypatch.setattr(invitations, "now", lambda: later)
        elif state == "revoked":
            as_user(team.owner).post(invitations_url(team, f"{created['id']}/revoke/"))
        else:
            accept(token, new_account_body())
        responses = [preview(token), accept(token, new_account_body("Other"))]
        for response in responses:
            assert response.status_code == 404
            assert response.json()["code"] == "invitation_invalid"
            assert response["Cache-Control"] == "no-store, private"

    def test_new_account(self, team: Team, as_user: Any) -> None:
        invite(as_user(team.admin), team, role(team.org, "member"), team.auditors)
        token = deliver()[NEWCOMER]
        response = accept(token, {"full_name": "  New Person ", "password": NEW_PASSWORD})
        assert response.status_code == 200
        assert response.json()["account_created"] is True
        user = User.objects.get(email=NEWCOMER)
        assert user.full_name == "New Person"
        assert user.is_active
        assert not user.is_staff
        assert not user.is_superuser
        assert user.password_changed_at is not None
        membership = Membership.objects.get(organization=team.org, user=user)
        assert set(
            MembershipRole.objects.filter(membership=membership).values_list("role_id", flat=True)
        ) == {role(team.org, "member").pk, team.auditors.pk}
        assert {
            link.assigned_by_id for link in MembershipRole.objects.filter(membership=membership)
        } == {team.admin.pk}
        # The new account signs in normally afterwards.
        login = Client().post(
            "/api/v1/auth/login/",
            {"email": NEWCOMER, "password": NEW_PASSWORD},
            content_type="application/json",
        )
        assert login.status_code == 200
        assert audit_actions(team.org)[-3:] == [
            "invitation.accepted",
            "rbac.membership.created",
            "rbac.membership.roles_assigned",
        ]
        created = AuditLog.objects.filter(action="auth.account.created", target_id=str(user.pk))
        assert created.exists()

    @pytest.mark.parametrize(
        ("body", "field"),
        [
            ({"password": NEW_PASSWORD}, "full_name"),
            ({"full_name": "N"}, "password"),
            ({"full_name": "N", "password": "short"}, "password"),
            ({"full_name": "N", "password": "newcomer@example.org"}, "password"),
            ({**new_account_body(), "email": "other@example.org"}, "email"),
            ({**new_account_body(), "is_staff": True}, "is_staff"),
            ({**new_account_body(), "is_superuser": True}, "is_superuser"),
            ({**new_account_body(), "is_active": False}, "is_active"),
        ],
    )
    def test_new_account_validation(
        self, team: Team, as_user: Any, body: dict[str, Any], field: str
    ) -> None:
        invite(as_user(team.owner), team, team.auditors)
        token = deliver()[NEWCOMER]
        response = accept(token, body)
        assert response.status_code == 400, response.content
        assert field in str(response.json())
        assert not User.objects.filter(email=NEWCOMER).exists()
        assert accept(token, new_account_body()).status_code == 200  # still pending

    def test_existing_account_must_sign_in_as_itself(self, team: Team, as_user: Any) -> None:
        invited = team.other_owner
        invite(as_user(team.owner), team, team.auditors, email=invited.email)
        token = deliver()[invited.email]
        anonymous = accept(token)
        assert anonymous.status_code == 401, anonymous.content
        assert anonymous.json()["code"] == "sign_in_required"
        assert anonymous["WWW-Authenticate"].startswith("Bearer")
        # A password is never accepted for an existing account, signed in or not.
        assert accept(token, new_account_body()).status_code == 401
        assert accept(token, new_account_body(), user=invited).status_code == 400
        wrong = accept(token, user=team.outsider)
        assert wrong.status_code == 403
        assert wrong.json()["code"] == "invitation_email_mismatch"
        response = accept(token, user=invited)
        assert response.status_code == 200
        assert response.json()["account_created"] is False
        assert Membership.objects.filter(organization=team.org, user=invited).exists()
        assert User.objects.filter(email=invited.email).count() == 1

    def test_signed_in_user_cannot_create_another_account(self, team: Team, as_user: Any) -> None:
        invite(as_user(team.owner), team, team.auditors)
        token = deliver()[NEWCOMER]
        response = accept(token, new_account_body(), user=team.outsider)
        assert response.status_code == 403
        assert not User.objects.filter(email=NEWCOMER).exists()

    def test_member_by_the_time_of_acceptance(self, team: Team, as_user: Any) -> None:
        invited = team.other_owner
        invite(as_user(team.owner), team, team.auditors, email=invited.email)
        token = deliver()[invited.email]
        member(team.org, invited)
        response = accept(token, user=invited)
        assert response.status_code == 409
        assert response.json()["code"] == "already_member"
        assert Membership.objects.filter(organization=team.org, user=invited).count() == 1

    def test_inviter_authority_is_revalidated(self, team: Team, as_user: Any) -> None:
        invite(as_user(team.admin), team, team.auditors)
        token = deliver()[NEWCOMER]
        admin_role = role(team.org, "admin")
        admin_role.permissions.remove(*admin_role.permissions.filter(code="audit.view"))
        response = accept(token, new_account_body())
        assert response.status_code == 409
        assert response.json()["code"] == "invitation_authority_revoked"
        assert not User.objects.filter(email=NEWCOMER).exists()  # nothing partial
        assert AuditLog.objects.filter(action="invitation.accept_rejected").exists()

    @pytest.mark.parametrize("change", ["suspended", "removed", "role_gained_permission"])
    def test_stale_inviter_fails_closed(self, team: Team, as_user: Any, change: str) -> None:
        invite(as_user(team.admin), team, team.auditors)
        token = deliver()[NEWCOMER]
        inviter = team.membership(team.admin)
        if change == "suspended":
            Membership.objects.filter(pk=inviter.pk).update(status="suspended")
        elif change == "removed":
            MembershipRole.objects.filter(membership=inviter).delete()
            Membership.objects.filter(pk=inviter.pk).delete()
        else:
            # The invited role gained a permission the inviter does not hold.
            admin_role = role(team.org, "admin")
            admin_role.permissions.remove(*admin_role.permissions.filter(code="roles.manage"))
            from apps.rbac.models import Permission  # noqa: PLC0415

            team.auditors.permissions.add(Permission.objects.get(code="roles.manage"))
        assert accept(token, new_account_body()).json()["code"] == "invitation_authority_revoked"

    def test_owner_invitation_requires_the_inviter_to_remain_owner(
        self, team: Team, as_user: Any
    ) -> None:
        invite(as_user(team.owner), team, role(team.org, "owner"))
        token = deliver()[NEWCOMER]
        co_owner = member(
            team.org,
            User.objects.create_user("co@example.org", "x" * 12, full_name="C"),
            role(team.org, "owner"),
        )
        MembershipRole.objects.filter(
            membership=team.membership(team.owner), role__system_key="owner"
        ).delete()
        assert co_owner is not None
        assert accept(token, new_account_body()).json()["code"] == "invitation_authority_revoked"

    def test_suspended_organization(self, team: Team, as_user: Any) -> None:
        invite(as_user(team.owner), team, team.auditors)
        token = deliver()[NEWCOMER]
        Organization.objects.filter(pk=team.org.pk).update(status=OrganizationStatus.SUSPENDED)
        assert accept(token, new_account_body()).status_code == 404
        response = as_user(team.owner).post(
            invitations_url(team), {"email": "x@example.org", "role_ids": [str(team.auditors.pk)]}
        )
        assert response.status_code == 404  # tenant API closed

    def test_only_the_latest_email_link_works(self, team: Team, as_user: Any) -> None:
        created = invite(as_user(team.owner), team, team.auditors)
        first = deliver()[NEWCOMER]
        invitation = Invitation.objects.get(pk=created["id"])
        # Simulate a resend (e.g. after a crash before the outcome was recorded).
        delivery = invitation.email_delivery
        type(delivery).objects.filter(pk=delivery.pk).update(status="pending", claim_id=None)
        second = deliver()[NEWCOMER]
        assert first != second
        assert preview(first).status_code == 404
        assert accept(second, new_account_body()).status_code == 200

    def test_rate_limited(self, team: Team, settings: Any) -> None:
        settings.AUTH_RATE_LIMITS = {**settings.AUTH_RATE_LIMITS, "invitation_ip": (2, 300)}
        assert preview("A" * 43).status_code == 404
        assert preview("A" * 43).status_code == 404
        limited = preview("A" * 43)
        assert limited.status_code == 429
        assert "Retry-After" in limited
        assert AuditLog.objects.filter(action="auth.rate_limited").exists()

    def test_no_secrets_reach_audit_or_logs(
        self, team: Team, as_user: Any, caplog: pytest.LogCaptureFixture
    ) -> None:
        invite(as_user(team.owner), team, team.auditors)
        token = deliver()[NEWCOMER]
        accept(token, new_account_body())
        invitation = Invitation.objects.get(email=NEWCOMER)
        rows = AuditLog.objects.values("action", "target_id", "metadata", "changes", "user_agent")
        text = " ".join(str(v) for row in rows for v in row.values())
        for secret in (token, invitation.token_hash or "", NEW_PASSWORD):
            assert secret not in text
            assert secret not in caplog.text
        # The address appears only as the Batch 5 actor snapshot, never in metadata or changes.
        assert NEWCOMER not in text
