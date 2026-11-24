"""Complete tenant-isolation matrix (plan §5.2, ADR-0003, ADR-0015, ADR-0019).

Extends the per-app matrices (``apps/rbac/tests/test_authorization_matrix.py``,
``apps/organizations/tests/test_tenant_isolation.py``) with:

- every caller category against every tenant endpoint, asserting that **denied mutations change
  nothing** (a snapshot of every tenant table) and record no success audit event;
- foreign nested identifiers (membership, role and invitation ids of organization B under
  organization A's URL), for the Owner of A, who holds every permission in A;
- cross-tenant identifiers inside request bodies;
- non-existent and malformed organization ids, and provisioning/suspended organizations;
- identical "not found" responses, so foreign tenants and resources cannot be enumerated.
"""

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import pytest
from django.utils import timezone

from apps.accounts.models import User
from apps.audit.models import AuditLog
from apps.organizations.models import (
    Invitation,
    InvitationEmail,
    InvitationRole,
    Membership,
    Organization,
)
from apps.organizations.tests.conftest import Api, bearer
from apps.rbac.models import MembershipRole, Role
from apps.rbac.tests.conftest import Team, custom_role, member, role, url

pytestmark = pytest.mark.django_db


def snapshot() -> dict[str, Any]:
    """Every row of every tenant table (and organization statuses), for side-effect checks."""
    return {
        "organizations": sorted(
            Organization.objects.values_list("id", "name", "status", "slug", "timezone")
        ),
        "memberships": sorted(Membership.objects.values_list("id", "organization_id", "status")),
        "membership_roles": sorted(MembershipRole.objects.values_list("membership_id", "role_id")),
        "roles": sorted(Role.objects.values_list("id", "organization_id", "name", "description")),
        "role_permissions": sorted(
            Role.permissions.through.objects.values_list("role_id", "permission_id")
        ),
        "invitations": sorted(Invitation.objects.values_list("id", "status", "token_hash")),
        "invitation_roles": sorted(InvitationRole.objects.values_list("invitation_id", "role_id")),
        "invitation_emails": sorted(InvitationEmail.objects.values_list("id", "status")),
        "users": sorted(User.objects.values_list("id", "email", "is_active")),
    }


SUCCESS_ACTIONS = (
    "organization.updated",
    "rbac.",
    "invitation.created",
    "invitation.revoked",
    "member",
)


def success_events() -> int:
    return sum(
        AuditLog.objects.filter(action__startswith=prefix, outcome="success").count()
        for prefix in SUCCESS_ACTIONS
    )


@dataclass
class World:
    team: Team
    victim: Membership  # an ordinary member of A
    pending: Invitation  # a pending invitation of A
    foreign_member: Membership  # a member of B
    foreign_role: Role  # a custom role of B
    foreign_invitation: Invitation  # a pending invitation of B


def _invitation(organization: Organization, inviter: User, email: str, granted: Role) -> Invitation:
    invitation = Invitation(
        organization=organization,
        email=email,
        invited_by=inviter,
        expires_at=timezone.now() + timedelta(days=7),
    )
    invitation.save()
    InvitationRole(organization=organization, invitation=invitation, role=granted).save()
    return invitation


@pytest.fixture
def world(team: Team) -> World:
    victim_user = User.objects.create_user("victim@example.org", "x" * 14, full_name="V")
    foreign_user = User.objects.create_user("foreign@example.org", "x" * 14, full_name="F")
    return World(
        team=team,
        victim=member(team.org, victim_user, role(team.org, "member")),
        pending=_invitation(team.org, team.owner, "pend-a@example.org", role(team.org, "member")),
        foreign_member=member(team.other, foreign_user, role(team.other, "member")),
        foreign_role=custom_role(team.other, "Foreign", "members.view"),
        foreign_invitation=_invitation(
            team.other, team.other_owner, "pend-b@example.org", role(team.other, "member")
        ),
    )


@dataclass(frozen=True)
class Call:
    name: str
    method: str
    path: Callable[[World], str]
    body: Callable[[World], Any] | None = None

    @property
    def mutates(self) -> bool:
        return self.method != "get"

    def send(self, client: Api, w: World) -> Any:
        handler = getattr(client, self.method)
        path = self.path(w)
        return handler(path, self.body(w)) if self.body is not None else handler(path)


def _a(w: World, path: str = "") -> str:
    return url(w.team.org, path)


CALLS = [
    Call("org-get", "get", _a),
    Call("org-patch", "patch", _a, lambda w: {"name": "Hijacked"}),
    Call("me", "get", lambda w: _a(w, "me/")),
    Call("audit", "get", lambda w: _a(w, "audit-logs/")),
    Call("members", "get", lambda w: _a(w, "members/")),
    Call("member-get", "get", lambda w: _a(w, f"members/{w.victim.pk}/")),
    Call(
        "member-suspend",
        "patch",
        lambda w: _a(w, f"members/{w.victim.pk}/"),
        lambda w: {"status": "suspended"},
    ),
    Call("member-remove", "delete", lambda w: _a(w, f"members/{w.victim.pk}/")),
    Call(
        "member-roles",
        "put",
        lambda w: _a(w, f"members/{w.victim.pk}/roles/"),
        lambda w: {"role_ids": [str(role(w.team.org, "admin").pk)]},
    ),
    Call("roles", "get", lambda w: _a(w, "roles/")),
    Call(
        "role-create",
        "post",
        lambda w: _a(w, "roles/"),
        lambda w: {"name": "Escalate", "permissions": ["roles.manage"]},
    ),
    Call("role-get", "get", lambda w: _a(w, f"roles/{w.team.auditors.pk}/")),
    Call(
        "role-patch",
        "patch",
        lambda w: _a(w, f"roles/{w.team.auditors.pk}/"),
        lambda w: {"permissions": ["members.manage", "roles.manage"]},
    ),
    Call("role-delete", "delete", lambda w: _a(w, f"roles/{w.team.auditors.pk}/")),
    Call("permissions", "get", lambda w: _a(w, "permissions/")),
    Call("invitations", "get", lambda w: _a(w, "invitations/")),
    Call(
        "invite",
        "post",
        lambda w: _a(w, "invitations/"),
        lambda w: {"email": "new@example.org", "role_ids": [str(role(w.team.org, "admin").pk)]},
    ),
    Call("invite-revoke", "post", lambda w: _a(w, f"invitations/{w.pending.pk}/revoke/")),
]
MUTATIONS = [c for c in CALLS if c.mutates]

# Callers who are not active members of an active organization A: always 404 (or 401).
OUTSIDERS = {
    "anonymous": 401,
    "inactive": 401,
    "suspended": 404,
    "other_owner": 404,
    "outsider": 404,
    "platform_admin": 404,
    "superuser": 404,
}


def _client(w: World, caller: str) -> Api:
    if caller == "anonymous":
        return Api({})
    return Api(bearer(getattr(w.team, caller)))


@pytest.mark.parametrize("call", CALLS, ids=[c.name for c in CALLS])
@pytest.mark.parametrize("caller", list(OUTSIDERS))
def test_outsiders_get_the_same_answer_and_change_nothing(
    world: World, caller: str, call: Call
) -> None:
    before, events = snapshot(), success_events()
    response = call.send(_client(world, caller), world)
    assert response.status_code == OUTSIDERS[caller], response.content
    body = response.json()
    expected_codes = (
        {"not_authenticated", "authentication_failed"}
        if OUTSIDERS[caller] == 401
        else {"not_found"}
    )
    assert body["code"] in expected_codes
    assert str(world.team.org.pk) not in response.content.decode()
    assert snapshot() == before
    assert success_events() == events


# Members of A holding too little for the mutation (the per-endpoint 403 is asserted elsewhere).
UNDERPRIVILEGED = ["member", "norole", "auditor"]


@pytest.mark.parametrize("call", MUTATIONS, ids=[c.name for c in MUTATIONS])
@pytest.mark.parametrize("caller", UNDERPRIVILEGED)
def test_denied_mutations_by_members_change_nothing(world: World, caller: str, call: Call) -> None:
    before, events = snapshot(), success_events()
    response = call.send(_client(world, caller), world)
    assert response.status_code == 403, response.content
    assert snapshot() == before
    assert success_events() == events


def test_custom_permission_role_grants_exactly_its_permissions(world: World) -> None:
    viewer = User.objects.create_user("viewer@example.org", "x" * 14, full_name="Viewer")
    member(world.team.org, viewer, custom_role(world.team.org, "Viewers", "members.view"))
    client = Api(bearer(viewer))
    assert client.get(_a(world, "members/")).status_code == 200
    assert client.get(_a(world, f"members/{world.victim.pk}/")).status_code == 200
    before = snapshot()
    assert (
        client.patch(_a(world, f"members/{world.victim.pk}/"), {"status": "suspended"}).status_code
        == 403
    )
    assert client.get(_a(world, "roles/")).status_code == 403
    assert client.get(_a(world, "audit-logs/")).status_code == 403
    assert client.get(_a(world)).status_code == 403  # organization.view not granted
    assert snapshot() == before


# --------------------------------------------------------------- foreign nested identifiers
FOREIGN_NESTED: list[tuple[str, Callable[[World], str], dict[str, Any] | None]] = [
    ("get", lambda w: f"members/{w.foreign_member.pk}/", None),
    ("patch", lambda w: f"members/{w.foreign_member.pk}/", {"status": "suspended"}),
    ("delete", lambda w: f"members/{w.foreign_member.pk}/", None),
    ("put", lambda w: f"members/{w.foreign_member.pk}/roles/", {"role_ids": []}),
    ("get", lambda w: f"roles/{w.foreign_role.pk}/", None),
    ("patch", lambda w: f"roles/{w.foreign_role.pk}/", {"name": "Renamed"}),
    ("delete", lambda w: f"roles/{w.foreign_role.pk}/", None),
    ("post", lambda w: f"invitations/{w.foreign_invitation.pk}/revoke/", None),
]


@pytest.mark.parametrize(
    ("method", "path", "body"),
    FOREIGN_NESTED,
    ids=[f"{m}-{i}" for i, (m, _p, _b) in enumerate(FOREIGN_NESTED)],
)
def test_foreign_nested_ids_are_not_found_for_the_owner(
    world: World, method: str, path: Callable[[World], str], body: Any
) -> None:
    """The Owner of A (every permission in A) addressing B's objects through A's URL."""
    client = Api(bearer(world.team.owner))
    before = snapshot()
    target = _a(world, path(world))
    response = getattr(client, method)(target, body) if body else getattr(client, method)(target)
    assert response.status_code == 404, response.content
    assert response.json()["code"] == "not_found"
    # Same answer as for an id that does not exist anywhere.
    missing = target.replace(
        target.split("/")[-2 if not target.endswith("revoke/") else -3], str(uuid.uuid4())
    )
    other = getattr(client, method)(missing, body) if body else getattr(client, method)(missing)
    assert other.status_code == 404
    assert set(other.json()) == set(response.json())
    assert other.json()["detail"] == response.json()["detail"]
    assert snapshot() == before


def test_foreign_role_ids_in_bodies_are_rejected_without_side_effects(world: World) -> None:
    client = Api(bearer(world.team.owner))
    foreign = str(world.foreign_role.pk)
    foreign_system = str(role(world.team.other, "admin").pk)
    before = snapshot()
    for body in (
        {"role_ids": [foreign]},
        {"role_ids": [foreign_system, str(role(world.team.org, "member").pk)]},
    ):
        response = client.put(_a(world, f"members/{world.victim.pk}/roles/"), body)
        assert response.status_code == 400, response.content
        response = client.post(_a(world, "invitations/"), {"email": "x@example.org", **body})
        assert response.status_code == 400, response.content
    assert snapshot() == before


def test_foreign_ids_are_indistinguishable_from_unknown_ids_in_bodies(world: World) -> None:
    client = Api(bearer(world.team.owner))
    path = _a(world, f"members/{world.victim.pk}/roles/")
    foreign = client.put(path, {"role_ids": [str(world.foreign_role.pk)]}).json()
    unknown = client.put(path, {"role_ids": [str(uuid.uuid4())]}).json()
    assert foreign["code"] == unknown["code"]
    assert [e["detail"] for e in foreign["errors"]] == [e["detail"] for e in unknown["errors"]]


# --------------------------------------------------------------- organization ids
@pytest.mark.parametrize(
    "org_id", [str(uuid.uuid4()), "00000000-0000-0000-0000-000000000000", "not-a-uuid", "1"]
)
def test_unknown_and_malformed_organizations(world: World, org_id: str) -> None:
    client = Api(bearer(world.team.owner))
    for path in ("", "me/", "members/", "roles/", "invitations/", "audit-logs/"):
        response = client.get(f"/api/v1/organizations/{org_id}/{path}")
        assert response.status_code == 404


@pytest.mark.parametrize("status", ["provisioning", "suspended"])
@pytest.mark.parametrize("call", CALLS, ids=[c.name for c in CALLS])
def test_closed_organizations_change_nothing_even_for_owners(
    world: World, status: str, call: Call
) -> None:
    Organization.objects.filter(pk=world.team.org.pk).update(status=status)
    before, events = snapshot(), success_events()
    response = call.send(Api(bearer(world.team.owner)), world)
    assert response.status_code == 404
    assert snapshot() == before
    assert success_events() == events


def test_organization_listing_never_shows_other_tenants(world: World) -> None:
    for caller, expected in (
        ("owner", {"acme"}),
        ("admin", {"acme", "globex"}),
        ("other_owner", {"globex"}),
        ("outsider", set()),
        ("platform_admin", set()),
        ("superuser", set()),
        ("suspended", set()),
    ):
        response = Api(bearer(getattr(world.team, caller))).get("/api/v1/organizations/")
        assert response.status_code == 200
        assert {o["organization"]["slug"] for o in response.json()["results"]} == expected, caller


def test_bodies_cannot_redirect_the_tenant(world: World) -> None:
    client = Api(bearer(world.team.owner))
    before = snapshot()
    for key in ("organization", "organization_id", "org", "org_id", "tenant"):
        response = client.post(
            _a(world, "roles/"), {"name": "X", "permissions": [], key: str(world.team.other.pk)}
        )
        assert response.status_code == 400
    assert snapshot() == before
