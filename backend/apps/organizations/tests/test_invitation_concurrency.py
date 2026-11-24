"""Invitation concurrency on real PostgreSQL transactions (ADR-0018).

Threads are released together by a barrier and use their own connections. A deadlock would
surface as ``DatabaseError`` ("deadlock detected") and fail the test.
"""

from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from django.db import DatabaseError

from apps.accounts.models import User
from apps.accounts.services import deactivate_user
from apps.organizations import invitations
from apps.organizations.exceptions import (
    AccountInactiveError,
    InvitationAlreadyPendingError,
    InvitationAuthorityRevokedError,
    InvitationNotFoundError,
    OrganizationNotProvisioningError,
    SignInRequiredError,
)
from apps.organizations.models import (
    Invitation,
    InvitationStatus,
    Membership,
    Organization,
    OrganizationStatus,
)
from apps.organizations.services import create_organization
from apps.rbac import services as rbac
from apps.rbac.models import MembershipRole, SystemRole
from apps.rbac.tests.conftest import member, role
from apps.rbac.tests.test_concurrency import run_together

from .invitation_helpers import NEW_PASSWORD, deliver

pytestmark = pytest.mark.django_db(transaction=True)
EMAIL = "racer@example.org"
EXPECTED = (
    InvitationNotFoundError,
    SignInRequiredError,
    InvitationAlreadyPendingError,
    InvitationAuthorityRevokedError,
    AccountInactiveError,
    OrganizationNotProvisioningError,
)


def outcome(results: list[Any]) -> tuple[list[Any], list[BaseException]]:
    failures = [r for r in results if isinstance(r, BaseException)]
    assert not [f for f in failures if isinstance(f, DatabaseError)], failures
    assert all(isinstance(f, EXPECTED) for f in failures), failures
    return [r for r in results if not isinstance(r, BaseException)], failures


@pytest.fixture
def active_org(make_org: Callable[..., Organization], make_user: Callable[..., User]) -> Any:
    organization = make_org(slug="race")
    owner = member(organization, make_user("owner@race.org"), role(organization, SystemRole.OWNER))
    admin = member(organization, make_user("admin@race.org"), role(organization, SystemRole.ADMIN))
    return organization, owner.user, admin.user


def _invite(organization: Organization, actor: User, *roles: Any, email: str = EMAIL) -> str:
    invitations.create_invitation(
        actor=actor, organization=organization, email=email, role_ids=[r.pk for r in roles]
    )
    return deliver()[email]


def _new_account(token: str, name: str = "Racer") -> Callable[[], Any]:
    return lambda: invitations.accept_invitation(token, full_name=name, password=NEW_PASSWORD)


def test_double_acceptance_with_new_accounts(active_org: Any) -> None:
    organization, owner, _admin = active_org
    token = _invite(organization, owner, role(organization, SystemRole.MEMBER))
    accepted, failures = outcome(run_together(_new_account(token, "A"), _new_account(token, "B")))
    assert len(accepted) == 1
    assert len(failures) == 1
    assert User.objects.filter(email=EMAIL).count() == 1
    assert Membership.objects.filter(organization=organization, user__email=EMAIL).count() == 1


def test_double_acceptance_by_an_existing_account(
    active_org: Any, make_user: Callable[..., User]
) -> None:
    organization, owner, _admin = active_org
    invitee = make_user(EMAIL)
    token = _invite(organization, owner, role(organization, SystemRole.MEMBER))

    def accept() -> Any:
        return invitations.accept_invitation(token, user=invitee)

    accepted, failures = outcome(run_together(accept, accept))
    assert len(accepted) == 1
    assert [type(f) for f in failures] == [InvitationNotFoundError]
    assert Membership.objects.filter(organization=organization, user=invitee).count() == 1


def test_acceptance_racing_revocation(active_org: Any) -> None:
    organization, owner, _admin = active_org
    token = _invite(organization, owner, role(organization, SystemRole.MEMBER))
    invitation = Invitation.objects.get(email=EMAIL)
    results = run_together(
        _new_account(token),
        lambda: invitations.revoke_invitation(
            actor=owner, organization=organization, invitation_id=invitation.pk
        ),
    )
    invitation.refresh_from_db()
    if isinstance(results[0], BaseException):  # revoked first
        assert isinstance(results[0], InvitationNotFoundError)
        assert invitation.status == InvitationStatus.REVOKED
        assert not User.objects.filter(email=EMAIL).exists()
    else:  # accepted first: revocation is refused and the membership stands
        assert invitation.status == InvitationStatus.ACCEPTED
        assert type(results[1]).__name__ == "InvitationNotPendingError"
        assert Membership.objects.filter(organization=organization, user__email=EMAIL).exists()


def test_expiry_boundary(active_org: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    organization, owner, _admin = active_org
    token = _invite(organization, owner, role(organization, SystemRole.MEMBER))
    expires_at = Invitation.objects.get(email=EMAIL).expires_at
    monkeypatch.setattr(invitations, "now", lambda: expires_at)
    with pytest.raises(InvitationNotFoundError):
        _new_account(token)()
    monkeypatch.setattr(invitations, "now", lambda: expires_at - timedelta(microseconds=1))
    assert _new_account(token)().account_created


def test_concurrent_invitations_for_the_same_address(active_org: Any) -> None:
    organization, owner, admin = active_org
    member_role = role(organization, SystemRole.MEMBER)

    def invite(actor: User) -> Callable[[], Any]:
        return lambda: invitations.create_invitation(
            actor=actor, organization=organization, email=EMAIL, role_ids=[member_role.pk]
        )

    created, failures = outcome(run_together(invite(owner), invite(admin), invite(owner)))
    assert len(created) == 1
    assert len(failures) == 2
    assert Invitation.objects.filter(email=EMAIL, status=InvitationStatus.PENDING).count() == 1


def test_acceptance_racing_account_registration(active_org: Any) -> None:
    organization, owner, _admin = active_org
    token = _invite(organization, owner, role(organization, SystemRole.MEMBER))

    def register() -> Any:
        return User.objects.create_user(EMAIL, NEW_PASSWORD, full_name="Registered")

    results = run_together(_new_account(token), register)
    assert User.objects.filter(email=EMAIL).count() == 1
    accepted = [r for r in results if isinstance(r, invitations.AcceptanceResult)]
    if not accepted:
        assert isinstance(results[0], SignInRequiredError)
        assert not Membership.objects.filter(organization=organization, user__email=EMAIL).exists()


def test_acceptance_racing_deactivation(active_org: Any, make_user: Callable[..., User]) -> None:
    organization, owner, _admin = active_org
    invitee = make_user(EMAIL)
    token = _invite(organization, owner, role(organization, SystemRole.MEMBER))
    results = run_together(
        lambda: invitations.accept_invitation(token, user=invitee),
        lambda: deactivate_user(invitee),
    )
    outcome(results)
    invitee.refresh_from_db()
    assert not invitee.is_active
    granted = Membership.objects.filter(organization=organization, user=invitee).exists()
    # Either the membership was created before the deactivation, or the acceptance was refused.
    assert granted != isinstance(results[0], AccountInactiveError)


def test_simultaneous_initial_owner_acceptances(platform_admin: User) -> None:
    organization = create_organization(
        actor=platform_admin,
        name="Initial",
        slug="initial",
        organization_type="other",
        initial_owner_email=EMAIL,
    )
    token = deliver()[EMAIL]
    accepted, _failures = outcome(
        run_together(_new_account(token, "A"), _new_account(token, "B"), _new_account(token, "C"))
    )
    assert len(accepted) == 1
    organization.refresh_from_db()
    assert organization.status == OrganizationStatus.ACTIVE
    owners = MembershipRole.objects.filter(
        organization=organization, role__system_key=SystemRole.OWNER
    )
    assert owners.count() == 1


def test_initial_acceptance_racing_reissue(platform_admin: User) -> None:
    organization = create_organization(
        actor=platform_admin,
        name="Initial",
        slug="initial",
        organization_type="other",
        initial_owner_email=EMAIL,
    )
    token = deliver()[EMAIL]
    results = run_together(
        _new_account(token),
        lambda: invitations.reissue_initial_owner_invitation(
            actor=platform_admin, organization=organization, email="other@example.org"
        ),
    )
    outcome(results)
    organization.refresh_from_db()
    if isinstance(results[0], BaseException):
        assert organization.status == OrganizationStatus.PROVISIONING
        assert (
            Invitation.objects.filter(
                organization=organization, status=InvitationStatus.PENDING
            ).count()
            == 1
        )
    else:
        assert organization.status == OrganizationStatus.ACTIVE
        assert isinstance(results[1], OrganizationNotProvisioningError)


def test_acceptance_racing_a_role_change_of_the_inviter(active_org: Any) -> None:
    organization, owner, admin = active_org
    auditors = role(organization, SystemRole.MEMBER)
    from apps.rbac.tests.conftest import custom_role  # noqa: PLC0415

    auditors = custom_role(organization, "Auditors", "audit.view")
    token = _invite(organization, admin, auditors)
    admin_role = role(organization, SystemRole.ADMIN)
    remaining = sorted(set(admin_role.permissions.values_list("code", flat=True)) - {"audit.view"})
    results = run_together(
        _new_account(token),
        lambda: rbac.update_role(
            actor=owner,
            organization=organization,
            role_id=admin_role.pk,
            changes={"permissions": remaining},
        ),
    )
    outcome(results)
    joined = Membership.objects.filter(organization=organization, user__email=EMAIL).exists()
    assert joined != isinstance(results[0], InvitationAuthorityRevokedError)


def test_mixed_invitation_and_rbac_operations_do_not_deadlock(
    active_org: Any, make_user: Callable[..., User]
) -> None:
    organization, owner, admin = active_org
    member_role = role(organization, SystemRole.MEMBER)
    existing = make_user("existing@race.org")
    tokens = {
        email: _invite(organization, owner, member_role, email=email)
        for email in ("existing@race.org", "new@race.org")
    }
    target = member(organization, make_user("target@race.org"), member_role)
    calls = [
        lambda: invitations.accept_invitation(tokens["existing@race.org"], user=existing),
        lambda: invitations.accept_invitation(
            tokens["new@race.org"], full_name="N", password=NEW_PASSWORD
        ),
        lambda: deactivate_user(existing),
        lambda: rbac.update_membership_status(
            actor=admin, organization=organization, membership_id=target.pk, status="suspended"
        ),
        lambda: invitations.create_invitation(
            actor=owner,
            organization=organization,
            email="third@race.org",
            role_ids=[member_role.pk],
        ),
        lambda: rbac.create_role(actor=owner, organization=organization, name="Late"),
    ]
    for result in run_together(*calls):
        assert not isinstance(result, DatabaseError), result
    assert rbac.active_owner_ids(organization)
