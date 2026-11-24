"""AEMS-017: reading the organization profile requires ``organization.view``; ``me/`` does not."""

from collections.abc import Callable
from typing import Any

import pytest

from apps.accounts.models import User
from apps.organizations.models import Organization, OrganizationStatus
from apps.organizations.tests.conftest import Api, bearer

from .conftest import Team, custom_role, member, role, url

pytestmark = pytest.mark.django_db


def profile(client: Api, organization: Organization) -> Any:
    return client.get(url(organization))


def _user(email: str) -> User:
    return User.objects.create_user(email, "Correct-Horse-Battery-42", full_name="U")


@pytest.mark.parametrize("caller", ["owner", "admin", "member"])
def test_system_roles_holding_the_permission_can_read(
    team: Team, as_user: Callable[..., Api], caller: str
) -> None:
    response = profile(as_user(getattr(team, caller)), team.org)
    assert response.status_code == 200
    assert response.json()["id"] == str(team.org.pk)


def test_member_role_keeps_organization_view_by_default(team: Team) -> None:
    assert role(team.org, "member").permissions.filter(code="organization.view").exists()


def test_custom_roles_with_and_without_the_permission(
    team: Team, as_user: Callable[..., Api]
) -> None:
    readers = member(
        team.org,
        _user("readers@example.org"),
        custom_role(team.org, "Readers", "organization.view"),
    )
    assert profile(as_user(readers.user), team.org).status_code == 200
    # The "Auditors" custom role holds audit.view only.
    response = profile(as_user(team.auditor), team.org)
    assert response.status_code == 403
    assert response.json()["code"] == "permission_denied"


def test_member_without_roles_is_denied(team: Team, as_user: Callable[..., Api]) -> None:
    response = profile(as_user(team.norole), team.org)
    assert response.status_code == 403
    assert response.json()["code"] == "permission_denied"


def test_losing_organization_view_takes_effect_on_the_next_request(
    team: Team, as_user: Callable[..., Api]
) -> None:
    client = as_user(team.member)
    assert profile(client, team.org).status_code == 200
    member_role = role(team.org, "member")
    member_role.permissions.remove(*member_role.permissions.filter(code="organization.view"))
    assert profile(client, team.org).status_code == 403


def test_suspended_membership_is_404(team: Team, as_user: Callable[..., Api]) -> None:
    assert profile(as_user(team.suspended), team.org).status_code == 404


@pytest.mark.parametrize("status", [OrganizationStatus.SUSPENDED, OrganizationStatus.PROVISIONING])
def test_inactive_organizations_are_404(
    team: Team, as_user: Callable[..., Api], status: str
) -> None:
    client = as_user(team.owner)
    Organization.objects.filter(pk=team.org.pk).update(status=status)
    assert profile(client, team.org).status_code == 404


@pytest.mark.parametrize("caller", ["outsider", "other_owner", "platform_admin", "superuser"])
def test_non_members_and_other_tenants_are_404(
    team: Team, as_user: Callable[..., Api], caller: str
) -> None:
    response = profile(as_user(getattr(team, caller)), team.org)
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"


def test_unauthenticated_and_deactivated_callers_are_401(
    team: Team, as_user: Callable[..., Api]
) -> None:
    assert profile(as_user(None), team.org).status_code == 401
    assert profile(Api(bearer(team.inactive)), team.org).status_code == 401


@pytest.mark.parametrize("caller", ["owner", "admin", "member", "auditor", "norole"])
def test_me_stays_available_to_every_active_member(
    team: Team, as_user: Callable[..., Api], caller: str
) -> None:
    response = as_user(getattr(team, caller)).get(url(team.org, "me/"))
    assert response.status_code == 200
    body = response.json()
    assert body["organization"]["id"] == str(team.org.pk)
    held = "organization.view" in body["permissions"]
    assert held == (caller in {"owner", "admin", "member"})


def test_me_without_organization_view_after_revocation(
    team: Team, as_user: Callable[..., Api]
) -> None:
    member_role = role(team.org, "member")
    member_role.permissions.clear()
    response = as_user(team.member).get(url(team.org, "me/"))
    assert response.status_code == 200
    assert response.json()["permissions"] == []
