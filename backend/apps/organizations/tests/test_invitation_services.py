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
