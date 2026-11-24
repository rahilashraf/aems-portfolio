"""Service-level invitation edges that the API cannot reach directly (defence in depth)."""

from typing import Any

import pytest
from django.db import IntegrityError
from rest_framework import exceptions

from apps.accounts.models import User
from apps.organizations import invitations
from apps.organizations.exceptions import (
    AccountInactiveError,
    InvitationAuthorityRevokedError,
    InvitationNotFoundError,
    OrganizationNotProvisioningError,
    OrganizationUnavailableError,
)
from apps.organizations.models import Invitation, InvitationRole, Organization
from apps.organizations.services import create_organization
from apps.rbac.tests.conftest import Team, role

from .invitation_helpers import NEW_PASSWORD, deliver

pytestmark = pytest.mark.django_db
EMAIL = "edge@example.org"


def _invite(team: Team, **kwargs: Any) -> Invitation:
    return invitations.create_invitation(
        actor=team.owner,
        organization=team.org,
        email=kwargs.get("email", EMAIL),
        role_ids=kwargs.get("role_ids", [team.auditors.pk]),
    )


def test_service_validates_input(team: Team) -> None:
    with pytest.raises(exceptions.ValidationError, match="email"):
        _invite(team, email="nope")
    with pytest.raises(exceptions.ValidationError, match="role_ids"):
        _invite(team, role_ids=[])
    with pytest.raises(exceptions.ValidationError, match="role_ids"):
        _invite(team, role_ids=[team.auditors.pk] + [r.pk for r in [role(team.other, "member")]])


def test_inactive_organization_and_unexpected_errors(
    team: Team, monkeypatch: pytest.MonkeyPatch
) -> None:
    Organization.objects.filter(pk=team.org.pk).update(status="suspended")
    with pytest.raises(OrganizationUnavailableError):
        _invite(team)
    Organization.objects.filter(pk=team.org.pk).update(status="active")

    def other_violation(*_args: Any, **_kwargs: Any) -> None:
        raise IntegrityError("another constraint")

    monkeypatch.setattr(Invitation, "save", other_violation)
    with pytest.raises(IntegrityError, match="another constraint"):
        _invite(team)


def test_initial_owner_rules(team: Team, platform_admin: User) -> None:
    with pytest.raises(OrganizationNotProvisioningError):
        invitations.issue_initial_owner_invitation(
            actor=platform_admin, organization=team.org, email=EMAIL
        )
    organization = create_organization(
        actor=platform_admin,
        name="P",
        slug="p-org",
        organization_type="other",
        initial_owner_email=EMAIL,
    )
    initial = Invitation.objects.get(organization=organization)
    # The tenant revocation path never touches initial Owner invitations (built directly here:
    # an active organization never has one through the services).
    stray = Invitation(
        organization=team.org,
        email="stray@example.org",
        invited_by=platform_admin,
        is_initial_owner=True,
        expires_at=initial.expires_at,
    )
    stray.save()
    with pytest.raises(exceptions.NotFound):
        invitations.revoke_invitation(
            actor=team.owner, organization=team.org, invitation_id=stray.pk
        )
    # An initial Owner invitation that would grant anything besides Owner fails closed.
    extra = role(organization, "admin")
    InvitationRole(organization=organization, invitation=initial, role=extra).save()
    token = deliver()[EMAIL]
    with pytest.raises(InvitationAuthorityRevokedError):
        invitations.accept_invitation(token, full_name="N", password=NEW_PASSWORD)


def test_inactive_account_is_refused_under_lock(team: Team, make_user: Any) -> None:
    invitee = make_user(EMAIL)
    _invite(team)
    token = deliver()[EMAIL]
    User.objects.filter(pk=invitee.pk).update(is_active=False)
    with pytest.raises(AccountInactiveError):
        invitations.accept_invitation(token, user=invitee)


def test_token_superseded_between_lookup_and_lock(
    team: Team, monkeypatch: pytest.MonkeyPatch
) -> None:
    _invite(team)
    token = deliver()[EMAIL]
    real = invitations._find_by_token

    def find_then_rotate(value: str) -> Any:
        found = real(value)
        Invitation.objects.filter(email=EMAIL).update(token_hash="0" * 64)
        return found

    monkeypatch.setattr(invitations, "_find_by_token", find_then_rotate)
    with pytest.raises(InvitationNotFoundError):
        invitations.accept_invitation(token, full_name="N", password=NEW_PASSWORD)
    assert not User.objects.filter(email=EMAIL).exists()


def test_organization_suspended_between_lookup_and_lock(
    team: Team, monkeypatch: pytest.MonkeyPatch
) -> None:
    _invite(team)
    token = deliver()[EMAIL]
    real = invitations._find_by_token

    def find_then_suspend(value: str) -> Any:
        found = real(value)
        Organization.objects.filter(pk=team.org.pk).update(status="suspended")
        return found

    monkeypatch.setattr(invitations, "_find_by_token", find_then_suspend)
    with pytest.raises(OrganizationUnavailableError):
        invitations.accept_invitation(token, full_name="N", password=NEW_PASSWORD)


def test_tokens_and_masking() -> None:
    token = invitations.new_token()
    assert len(token) == 43
    assert invitations.hash_token(token) != token
    assert len(invitations.hash_token(token)) == 64
    assert invitations._find_by_token(None) is None  # type: ignore[arg-type]
    assert invitations.mask_email("a@example.org") == "a*@example.org"
    assert invitations.mask_email("alice@example.org") == "a****@example.org"


# ------------------------------------------------------------------------------- AEMS-018
def test_email_changed_before_acceptance_is_rejected(team: Team, make_user: Any) -> None:
    from apps.organizations.exceptions import InvitationEmailMismatchError  # noqa: PLC0415
    from apps.organizations.models import Membership  # noqa: PLC0415

    invitee = make_user(EMAIL)
    _invite(team)
    token = deliver()[EMAIL]
    User.objects.filter(pk=invitee.pk).update(email="moved@elsewhere.org")
    with pytest.raises(InvitationEmailMismatchError):
        invitations.accept_invitation(token, user=User.objects.get(pk=invitee.pk))
    assert Invitation.objects.get(email=EMAIL).status == "pending"
    assert not Membership.objects.filter(organization=team.org, user=invitee).exists()


def test_email_changed_between_lookup_and_lock_is_rejected_under_the_lock(
    team: Team, make_user: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deterministic variant of the threaded race: the change lands after the unlocked match."""
    from apps.audit.models import AuditLog  # noqa: PLC0415
    from apps.organizations.exceptions import InvitationEmailMismatchError  # noqa: PLC0415
    from apps.organizations.models import Membership  # noqa: PLC0415
    from apps.rbac.models import MembershipRole  # noqa: PLC0415

    invitee = make_user(EMAIL)
    _invite(team)
    token = deliver()[EMAIL]
    real = invitations._accept_locked

    def change_then_accept(*args: Any, **kwargs: Any) -> Any:
        User.objects.filter(pk=invitee.pk).update(email="moved@elsewhere.org")
        return real(*args, **kwargs)

    monkeypatch.setattr(invitations, "_accept_locked", change_then_accept)
    with pytest.raises(InvitationEmailMismatchError):
        invitations.accept_invitation(token, user=invitee)
    assert Invitation.objects.get(email=EMAIL).status == "pending"
    assert not Membership.objects.filter(organization=team.org, user=invitee).exists()
    assert not MembershipRole.objects.filter(membership__user=invitee).exists()
    assert not AuditLog.objects.filter(action="invitation.accepted").exists()
    rejected = AuditLog.objects.get(action="invitation.accept_rejected")
    assert rejected.metadata == {"reason": "invitation_email_mismatch"}
    assert "moved@elsewhere.org" not in str(rejected.metadata)
    # The account keeps its new address; the invitation can still go to its rightful owner.
    monkeypatch.undo()
    rightful = make_user(EMAIL)
    assert invitations.accept_invitation(token, user=rightful).account_created is False


def test_unchanged_email_accepts(team: Team, make_user: Any) -> None:
    invitee = make_user(EMAIL)
    _invite(team)
    result = invitations.accept_invitation(deliver()[EMAIL], user=invitee)
    assert result.membership.user_id == invitee.pk


# -------------------------------------------------------- historical invitation roles
def test_deleting_a_role_after_acceptance_removes_its_historical_invitation_link(
    team: Team,
) -> None:
    """Documents current behaviour (ADR-0018, "Historical role links").

    A role still granted by a pending invitation cannot be deleted. After acceptance the
    membership holds the role (and blocks deletion) until it is removed from the member; then the
    role can be deleted and the accepted invitation's ``InvitationRole`` row is removed with it
    (CASCADE). The invitation row itself is unchanged, and the audit history keeps the role ids
    the invitation granted.
    """
    from apps.audit.models import AuditLog  # noqa: PLC0415
    from apps.rbac import services as rbac  # noqa: PLC0415
    from apps.rbac.exceptions import RoleInUseError  # noqa: PLC0415
    from apps.rbac.tests.conftest import custom_role  # noqa: PLC0415

    spare = custom_role(team.org, "Spare", "members.view")
    invitation = _invite(team, role_ids=[spare.pk])
    result = invitations.accept_invitation(deliver()[EMAIL], full_name="N", password=NEW_PASSWORD)
    with pytest.raises(RoleInUseError):  # still held by the new member
        rbac.delete_role(actor=team.owner, organization=team.org, role_id=spare.pk)
    rbac.replace_membership_roles(
        actor=team.owner, organization=team.org, membership_id=result.membership.pk, role_ids=[]
    )
    rbac.delete_role(actor=team.owner, organization=team.org, role_id=spare.pk)

    invitation.refresh_from_db()
    assert invitation.status == "accepted"  # the invitation row is untouched
    assert not InvitationRole.objects.filter(invitation=invitation).exists()  # link removed
    created = AuditLog.objects.get(action="invitation.created", target_id=str(invitation.pk))
    assert created.metadata["roles_added"] == [str(spare.pk)]  # history kept in the audit log
    assigned = AuditLog.objects.get(action="rbac.membership.roles_assigned")
    assert assigned.metadata["roles_added"] == [str(spare.pk)]
    assert AuditLog.objects.filter(action="rbac.role.deleted", target_id=str(spare.pk)).exists()
