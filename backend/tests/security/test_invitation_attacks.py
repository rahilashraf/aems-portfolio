"""Invitation attack suite (plan §4.6, ADR-0018, ADR-0019).

Complements the Batch 7 tests (``apps/organizations/tests/test_member_invitations.py``,
``test_onboarding.py``, ``test_invitation_concurrency.py``, including the AEMS-018 races) with
token brute force and format attacks, privilege drift between issuance and acceptance, delivery
races, and secret leakage through logs and the admin.
"""

import secrets
import threading
from collections.abc import Callable
from typing import Any

import pytest
from django.core import mail
from django.db import connections
from django.test import Client, override_settings

from apps.accounts.models import User
from apps.audit.models import AuditLog
from apps.organizations import invitation_outbox, invitations
from apps.organizations.models import (
    Invitation,
    InvitationEmail,
    Membership,
    Organization,
)
from apps.organizations.tests.conftest import bearer
from apps.organizations.tests.invitation_helpers import (
    NEW_PASSWORD,
    accept,
    deliver,
    new_account_body,
    preview,
)
from apps.rbac import services as rbac
from apps.rbac.tests.conftest import Team, custom_role, member, role

pytestmark = pytest.mark.django_db
EMAIL = "invitee@example.org"


def _invite(
    team: Team, *, actor: User | None = None, roles: list[Any] | None = None, email: str = EMAIL
) -> Invitation:
    return invitations.create_invitation(
        actor=actor or team.owner,
        organization=team.org,
        email=email,
        role_ids=[r.pk for r in (roles or [role(team.org, "member")])],
    )


def _invalid(response: Any) -> dict[str, Any]:
    assert response.status_code == 404, response.content
    body: dict[str, Any] = response.json()
    assert body["code"] == "invitation_invalid"
    assert response["Cache-Control"] == "no-store, private"
    assert response["Referrer-Policy"] == "no-referrer"
    return {k: v for k, v in body.items() if k != "request_id"}


# ------------------------------------------------------------------------------- token attacks
@pytest.mark.parametrize(
    "token",
    [
        "x",
        "A" * 43,
        "A" * 44,
        "A" * 2000,
        "%00",
        "..%2F..%2Fetc%2Fpasswd",
        "' OR '1'='1",
        "0" * 64,  # a digest-shaped value: digests are never accepted as tokens
        "%F0%9F%92%A9",
    ],
)
def test_malformed_and_guessed_tokens_are_uniformly_invalid(team: Team, token: str) -> None:
    _invite(team)
    deliver()
    for response in (
        Client().get(f"/api/v1/invitations/{token}/"),
        Client().post(
            f"/api/v1/invitations/{token}/accept/",
            new_account_body(),
            content_type="application/json",
        ),
    ):
        assert response.status_code == 404
    assert not User.objects.filter(email=EMAIL).exists()


def test_stored_digest_is_not_a_usable_token(team: Team) -> None:
    invitation = _invite(team)
    deliver()
    digest = Invitation.objects.get(pk=invitation.pk).token_hash
    assert digest
    _invalid(preview(digest))


def test_every_unusable_state_is_indistinguishable(team: Team) -> None:
    expired_or_used: list[dict[str, Any]] = []
    # Accepted.
    first = _invite(team, email="a1@example.org")
    t1 = deliver()["a1@example.org"]
    assert accept(t1, new_account_body()).status_code == 200
    expired_or_used.append(_invalid(preview(t1)))
    expired_or_used.append(_invalid(accept(t1, new_account_body())))
    # Revoked.
    second = _invite(team, email="a2@example.org")
    t2 = deliver()["a2@example.org"]
    invitations.revoke_invitation(actor=team.owner, organization=team.org, invitation_id=second.pk)
    expired_or_used.append(_invalid(preview(t2)))
    # Rotated (a newer email superseded the link).
    third = _invite(team, email="a3@example.org")
    t3 = deliver()["a3@example.org"]
    InvitationEmail.objects.filter(invitation=third).update(status="pending", claim_id=None)
    deliver()
    expired_or_used.append(_invalid(preview(t3)))
    # Expired.
    fourth = _invite(team, email="a4@example.org")
    t4 = deliver()["a4@example.org"]
    from datetime import timedelta  # noqa: PLC0415
    from unittest import mock  # noqa: PLC0415

    with mock.patch.object(
        invitations, "now", return_value=fourth.expires_at + timedelta(seconds=1)
    ):
        expired_or_used.append(_invalid(preview(t4)))
    # Never existed.
    expired_or_used.append(_invalid(preview(secrets.token_urlsafe(32))))
    assert all(body == expired_or_used[0] for body in expired_or_used)
    assert first.pk  # keep references alive for readability


def test_brute_force_is_rate_limited_per_ip(team: Team) -> None:
    with override_settings(AUTH_RATE_LIMITS={"invitation_ip": (5, 300)}):
        codes = [preview(secrets.token_urlsafe(32)).status_code for _ in range(8)]
        accept_code = (
            Client()
            .post(
                f"/api/v1/invitations/{secrets.token_urlsafe(32)}/accept/",
                new_account_body(),
                content_type="application/json",
            )
            .status_code
        )
    assert codes == [404] * 5 + [429] * 3
    assert accept_code == 429


def test_spoofed_forwarded_for_does_not_reset_the_limit(team: Team) -> None:
    with override_settings(AUTH_RATE_LIMITS={"invitation_ip": (3, 300)}, TRUSTED_PROXY_COUNT=0):
        codes = [
            Client()
            .get(
                f"/api/v1/invitations/{secrets.token_urlsafe(32)}/",
                HTTP_X_FORWARDED_FOR=f"203.0.113.{i}",
            )
            .status_code
            for i in range(5)
        ]
    assert codes == [404, 404, 404, 429, 429]


def test_double_acceptance_and_reuse(team: Team) -> None:
    _invite(team)
    token = deliver()[EMAIL]
    assert accept(token, new_account_body()).status_code == 200
    invitee = User.objects.get(email=EMAIL)
    assert accept(token, {}, user=invitee).status_code == 404
    assert accept(token, new_account_body()).status_code == 404
    assert Membership.objects.filter(organization=team.org, user=invitee).count() == 1


# ------------------------------------------------------------------------------- identity
def test_existing_account_cannot_be_claimed_with_the_token_alone(
    team: Team, make_user: Any
) -> None:
    victim = make_user(EMAIL)
    _invite(team)
    token = deliver()[EMAIL]
    response = accept(token, {"full_name": "Attacker", "password": NEW_PASSWORD})
    assert response.status_code == 401
    assert response.json()["code"] == "sign_in_required"
    fresh = User.objects.get(pk=victim.pk)
    assert not fresh.check_password(NEW_PASSWORD)
    assert fresh.full_name == victim.full_name
    assert not Membership.objects.filter(organization=team.org, user=victim).exists()


def test_wrong_signed_in_user_is_refused(team: Team) -> None:
    _invite(team)
    token = deliver()[EMAIL]
    response = accept(token, {}, user=team.outsider)
    assert response.status_code == 403
    assert response.json()["code"] == "invitation_email_mismatch"
    assert not Membership.objects.filter(organization=team.org, user=team.outsider).exists()


@pytest.mark.parametrize(
    "extra",
    [
        {"email": "attacker@evil.test"},
        {"is_staff": True},
        {"is_superuser": True},
        {"role_ids": []},
        {"organization": "x"},
    ],
)
def test_acceptance_body_cannot_choose_identity_or_privileges(
    team: Team, extra: dict[str, Any]
) -> None:
    _invite(team)
    token = deliver()[EMAIL]
    response = accept(token, {**new_account_body(), **extra})
    assert response.status_code == 400
    assert not User.objects.filter(email__in=[EMAIL, "attacker@evil.test"]).exists()


def test_granted_role_gaining_permissions_after_issuance_fails_closed(
    team: Team, make_user: Any
) -> None:
    """A delegated inviter's invitation is re-validated against the roles' permissions *at
    acceptance*: a role widened after issuance cannot smuggle permissions the inviter lacks."""
    inviter = make_user("inviter@example.org")
    member(
        team.org, inviter, custom_role(team.org, "Inviters", "invitations.manage", "members.view")
    )
    granted = custom_role(team.org, "Readers", "members.view")
    _invite(team, actor=inviter, roles=[granted])
    token = deliver()[EMAIL]
    rbac.update_role(
        actor=team.owner,
        organization=team.org,
        role_id=granted.pk,
        changes={"permissions": ["members.view", "audit.view"]},
    )
    response = accept(token, new_account_body())
    assert response.status_code == 409
    assert response.json()["code"] == "invitation_authority_revoked"
    assert Invitation.objects.get(email=EMAIL).status == "pending"
    assert not User.objects.filter(email=EMAIL).exists()


def test_non_owner_invitation_never_activates_a_provisioning_organization(
    team: Team, platform_admin: User
) -> None:
    from apps.organizations.services import create_organization  # noqa: PLC0415

    organization = create_organization(
        actor=platform_admin,
        name="Pending",
        slug="pending-org",
        organization_type="other",
        initial_owner_email="owner-to-be@example.org",
    )
    # A member invitation cannot even be created while provisioning...
    from apps.organizations.exceptions import OrganizationUnavailableError  # noqa: PLC0415

    with pytest.raises(OrganizationUnavailableError):
        invitations.create_invitation(
            actor=platform_admin,
            organization=organization,
            email=EMAIL,
            role_ids=[role(organization, "member").pk],
        )
    # ...and the initial invitation, once revoked, activates nothing.
    token = deliver()["owner-to-be@example.org"]
    invitations.revoke_initial_owner_invitation(actor=platform_admin, organization=organization)
    assert accept(token, new_account_body()).status_code == 404
    assert Organization.objects.get(pk=organization.pk).status == "provisioning"
    assert not Membership.objects.filter(organization=organization).exists()


def test_platform_staff_without_the_onboarding_permission_cannot_reissue(
    team: Team, make_user: Any
) -> None:
    from django.contrib.auth.models import Permission  # noqa: PLC0415

    staff = make_user("viewer-staff@example.org", is_staff=True)
    staff.user_permissions.add(Permission.objects.get(codename="view_organization"))
    org = Organization.objects.create(
        name="P", slug="p", organization_type="other", created_by=staff
    )
    client = Client()
    path = f"/api/v1/platform/organizations/{org.pk}/initial-owner-invitation/"
    response = client.post(
        path, {"email": "x@example.org"}, content_type="application/json", **bearer(staff)
    )
    assert response.status_code == 403
    assert not Invitation.objects.filter(organization=org).exists()


# ------------------------------------------------------------------------------- delivery races
def _run_together(*calls: Callable[[], Any]) -> list[Any]:
    barrier = threading.Barrier(len(calls))
    results: list[Any] = [None] * len(calls)

    def worker(index: int, call: Callable[[], Any]) -> None:
        try:
            barrier.wait(timeout=10)
            results[index] = call()
        except BaseException as exc:
            results[index] = exc
        finally:
            connections.close_all()

    threads = [threading.Thread(target=worker, args=(i, c)) for i, c in enumerate(calls)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
        assert not t.is_alive()
    return results


@pytest.mark.django_db(transaction=True)
def test_concurrent_delivery_workers_send_one_email(team: Team) -> None:
    _invite(team)
    _run_together(*(lambda: invitation_outbox.deliver_due(batch_size=10) for _ in range(4)))
    assert [m.to for m in mail.outbox] == [[EMAIL]]
    assert InvitationEmail.objects.get().status == "delivered"


@pytest.mark.django_db(transaction=True)
def test_revocation_racing_delivery_never_leaves_a_working_link(team: Team) -> None:
    invitation = _invite(team)
    results = _run_together(
        lambda: invitation_outbox.deliver_due(batch_size=10),
        lambda: invitations.revoke_invitation(
            actor=team.owner, organization=team.org, invitation_id=invitation.pk
        ),
    )
    assert not any(isinstance(r, BaseException) for r in results), results
    assert Invitation.objects.get(pk=invitation.pk).status == "revoked"
    for message in mail.outbox:  # if an email went out, its link is dead
        token = str(message.body).split("#token=")[1].split()[0]
        assert preview(token).status_code == 404


@pytest.mark.django_db(transaction=True)
def test_acceptance_racing_role_deletion(team: Team) -> None:
    granted = custom_role(team.org, "Temporary", "members.view")
    _invite(team, roles=[granted])
    token = deliver()[EMAIL]
    results = _run_together(
        lambda: accept(token, new_account_body(), raise_errors=False).status_code,
        lambda: rbac.delete_role(actor=team.owner, organization=team.org, role_id=granted.pk),
    )
    # The pending invitation protects the role: deletion is refused (409 role_in_use) whether it
    # runs first or after the acceptance assigned it to the new member.
    from apps.rbac.exceptions import RoleInUseError  # noqa: PLC0415

    assert results[0] == 200
    assert isinstance(results[1], RoleInUseError)
    from apps.rbac.models import MembershipRole  # noqa: PLC0415

    new_member = Membership.objects.get(organization=team.org, user__email=EMAIL)
    held = MembershipRole.objects.filter(membership=new_member).values_list("role_id", flat=True)
    assert set(held) == {granted.pk}


# ------------------------------------------------------------------------------- leakage
def test_tokens_and_digests_never_leak(team: Team, json_logs: Any, make_user: Any) -> None:
    root = team.superuser
    invitation = _invite(team)
    token = deliver()[EMAIL]
    digest = Invitation.objects.get(pk=invitation.pk).token_hash
    responses = [
        preview(token),
        accept(token, {"full_name": "N"}),  # validation error path
        accept(token, new_account_body()),
        accept(token, new_account_body()),  # now invalid: 404 path
        Client().get(f"/api/v1/organizations/{team.org.pk}/invitations/", **bearer(team.owner)),
    ]
    admin = Client()
    admin.force_login(root)
    responses.append(admin.get(f"/admin/organizations/invitation/{invitation.pk}/change/"))
    responses.append(admin.get("/admin/organizations/invitation/"))
    texts = [r.content.decode() for r in responses]
    texts.append(json_logs.text)
    texts.append(repr(list(AuditLog.objects.values())))
    texts.append(repr(list(InvitationEmail.objects.values())))
    for text in texts:
        assert token not in text
        assert digest not in text
