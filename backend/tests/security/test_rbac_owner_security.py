"""RBAC escalation and Owner-invariant attacks (plan §6, ADR-0005, ADR-0017, ADR-0019).

The pairwise Owner races of Batch 6 (``apps/rbac/tests/test_concurrency.py``) remain the primary
concurrency regressions. This suite adds API-level escalation attempts, deprecated-permission
handling, and a mixed stress test in which every ownership-reducing operation races every other.
"""

import itertools
import threading
from collections.abc import Callable
from typing import Any

import pytest
from django.db import DatabaseError, connections

from apps.accounts.models import User
from apps.accounts.services import deactivate_user
from apps.organizations.models import Membership, MembershipStatus, Organization
from apps.organizations.tests.conftest import Api, bearer
from apps.rbac import engine, services
from apps.rbac.exceptions import LastOwnerError, RbacForbiddenError
from apps.rbac.models import MembershipRole, Permission, Role, SystemRole
from apps.rbac.tests.conftest import Team, custom_role, member, role, url

pytestmark = pytest.mark.django_db


def _codes(membership: Membership) -> set[str]:
    codes, _is_owner = engine.fresh_permissions(membership.pk)
    return set(codes)


def _roles_of(membership: Membership) -> set[Any]:
    return set(
        MembershipRole.objects.filter(membership=membership).values_list("role_id", flat=True)
    )


# ------------------------------------------------------------------------------- escalation
class TestEscalationOverTheApi:
    def test_admin_cannot_promote_self_or_others_to_owner(self, team: Team) -> None:
        client = Api(bearer(team.admin))
        owner_role = str(role(team.org, SystemRole.OWNER).pk)
        for target in (team.membership(team.admin), team.membership(team.member)):
            response = client.put(
                url(team.org, f"members/{target.pk}/roles/"), {"role_ids": [owner_role]}
            )
            assert response.status_code == 403, response.content
            assert role(team.org, SystemRole.OWNER).pk not in _roles_of(target)

    def test_no_self_modification_even_for_owners(self, team: Team, make_user: Any) -> None:
        co_owner = make_user("co@example.org")
        member(team.org, co_owner, role(team.org, SystemRole.OWNER))
        own = team.membership(team.admin)
        client = Api(bearer(team.admin))
        for method, path, body in (
            (
                "put",
                f"members/{own.pk}/roles/",
                {"role_ids": [str(role(team.org, "admin").pk), str(team.auditors.pk)]},
            ),
            ("patch", f"members/{own.pk}/", {"status": "suspended"}),
        ):
            assert getattr(client, method)(url(team.org, path), body).status_code == 403

    def test_indirect_promotion_through_a_shared_role_is_refused(
        self, team: Team, make_user: Any
    ) -> None:
        """An actor who can edit a role they hold cannot add permissions they lack to it."""
        actor = make_user("manager@example.org")
        managers = custom_role(team.org, "Managers", "roles.manage", "roles.view")
        member(team.org, actor, managers)
        response = Api(bearer(actor)).patch(
            url(team.org, f"roles/{managers.pk}/"),
            {"permissions": ["roles.manage", "roles.view", "members.manage"]},
        )
        assert response.status_code == 403
        assert _codes(Membership.objects.get(user=actor)) == {"roles.manage", "roles.view"}

    def test_no_delegation_of_permissions_the_actor_lacks(self, team: Team, make_user: Any) -> None:
        actor = make_user("delegator@example.org")
        member(
            team.org, actor, custom_role(team.org, "Delegators", "members.manage", "members.view")
        )
        target = team.membership(team.norole)
        client = Api(bearer(actor))
        response = client.put(
            url(team.org, f"members/{target.pk}/roles/"), {"role_ids": [str(team.auditors.pk)]}
        )
        assert response.status_code == 403  # Auditors confers audit.view, which the actor lacks
        assert _roles_of(target) == set()
        response = client.post(
            url(team.org, "roles/"), {"name": "Sneaky", "permissions": ["audit.view"]}
        )
        assert response.status_code == 403

    def test_owner_role_is_immutable_even_for_owners(self, team: Team) -> None:
        owner_role = role(team.org, SystemRole.OWNER)
        client = Api(bearer(team.owner))
        path = url(team.org, f"roles/{owner_role.pk}/")
        assert client.patch(path, {"name": "Boss"}).status_code in (400, 403, 409)
        assert client.patch(path, {"description": "x"}).status_code in (400, 403, 409)
        assert client.patch(path, {"permissions": ["roles.view"]}).status_code in (400, 403, 409)
        assert client.delete(path).status_code in (400, 403, 409)
        # The Owner role stores no permission rows (it holds every active code dynamically), so
        # an empty list is a no-op that changes nothing.
        assert client.patch(path, {"permissions": []}).status_code == 200
        fresh = Role.objects.get(pk=owner_role.pk)
        assert (fresh.name, fresh.description) == (owner_role.name, owner_role.description)
        assert not fresh.permissions.exists()
        assert len(_codes(team.membership(team.owner))) == 8

    def test_platform_authority_never_reaches_tenant_services(self, team: Team) -> None:
        for actor in (team.platform_admin, team.superuser):
            with pytest.raises((RbacForbiddenError, Exception)):
                services.replace_membership_roles(
                    actor=actor,
                    organization=team.org,
                    membership_id=team.membership(team.member).pk,
                    role_ids=[role(team.org, SystemRole.OWNER).pk],
                )
        assert role(team.org, SystemRole.OWNER).pk not in _roles_of(team.membership(team.member))

    def test_services_enforce_rules_without_the_views(self, team: Team) -> None:
        """Defence in depth: calling the service directly applies the same rules."""
        with pytest.raises(RbacForbiddenError):
            services.create_role(actor=team.member, organization=team.org, name="X", permissions=[])
        with pytest.raises(RbacForbiddenError):
            services.update_membership_status(
                actor=team.admin,
                organization=team.org,
                membership_id=team.membership(team.owner).pk,
                status="suspended",
            )
        with pytest.raises(RbacForbiddenError):  # the Owner of B has no authority in A
            services.replace_membership_roles(
                actor=team.other_owner,
                organization=team.org,
                membership_id=team.membership(team.member).pk,
                role_ids=[],
            )


def test_deprecated_permissions_grant_nothing_immediately(team: Team) -> None:
    """AEMS-028: a code deprecated in the database was still granted to Owners (the Owner path
    used the registry only)."""
    Permission.objects.filter(code="members.view").update(is_deprecated=True)
    for caller in (team.owner, team.admin):
        assert Api(bearer(caller)).get(url(team.org, "members/")).status_code == 403
        assert "members.view" not in _codes(team.membership(caller))
    assert Api(bearer(team.owner)).get(url(team.org, "roles/")).status_code == 200


def test_roles_differ_per_organization(team: Team) -> None:
    """The Admin of A is an ordinary Member of B (Team fixture)."""
    assert "members.manage" in _codes(team.membership(team.admin))
    assert _codes(team.membership(team.admin, team.other)) == {"organization.view"}


# ------------------------------------------------------------------------------- stress
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
        t.join(timeout=90)
        assert not t.is_alive(), "a worker hung (lock wait or deadlock)"
    return results


def _active_owner_users(organization: Organization) -> set[Any]:
    return set(
        MembershipRole.objects.filter(
            organization=organization,
            role__system_key=SystemRole.OWNER,
            membership__status=MembershipStatus.ACTIVE,
            membership__user__is_active=True,
        ).values_list("membership__user_id", flat=True)
    )


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("round_", range(10))
def test_every_ownership_reducing_operation_racing_every_other(
    make_org: Callable[..., Organization], make_user: Callable[..., User], round_: int
) -> None:
    """Three Owners of A (one also the only Owner of B) each attempt a different reducing operation
    at the same moment. Whatever the interleaving, A and B keep an active Owner, nothing deadlocks,
    and every refusal is a domain error."""
    a, b = make_org(slug=f"a-{round_}"), make_org(slug=f"b-{round_}")
    o1, o2, o3 = (make_user(f"o{i}-{round_}@example.org") for i in (1, 2, 3))
    m1, m2, m3 = (member(a, u, role(a, SystemRole.OWNER)) for u in (o1, o2, o3))
    member(b, o3, role(b, SystemRole.OWNER))
    operations: list[Callable[[], Any]] = [
        lambda: services.replace_membership_roles(
            actor=o1, organization=a, membership_id=m2.pk, role_ids=[]
        ),
        lambda: services.update_membership_status(
            actor=o2, organization=a, membership_id=m3.pk, status="suspended"
        ),
        lambda: services.remove_membership(actor=o3, organization=a, membership_id=m1.pk),
        lambda: services.replace_membership_roles(
            actor=o2, organization=a, membership_id=m2.pk, role_ids=[]
        ),
        lambda: deactivate_user(User.objects.get(pk=o3.pk)),
        lambda: deactivate_user(User.objects.get(pk=o1.pk)),
    ]
    order = list(itertools.permutations(range(len(operations))))[round_ * 97 % 720]
    results = _run_together(*(operations[i] for i in order))
    unexpected = [
        r
        for r in results
        if isinstance(r, BaseException)
        and not isinstance(r, (LastOwnerError, RbacForbiddenError, Membership.DoesNotExist))
    ]
    assert unexpected == [], unexpected
    # AEMS-027: tenant mutations insert rows referencing the acting user (audit ``actor_id``),
    # which takes FOR KEY SHARE on the user row while the organization is locked. User and
    # organization locks are FOR NO KEY UPDATE, which never conflicts with those foreign-key
    # checks, so no ordering cycle (deadlock) can form.
    assert not any(isinstance(r, DatabaseError) for r in results), results
    assert _active_owner_users(a), "organization A lost its last active Owner"
    assert _active_owner_users(b), "organization B lost its last active Owner"


def test_user_and_organization_locks_do_not_block_foreign_key_checks() -> None:
    """AEMS-027: every serialization lock on users and organizations is FOR NO KEY UPDATE."""
    import ast  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    root = Path(__file__).resolve().parents[2] / "apps"
    offenders = []
    for path in root.rglob("*.py"):
        if "tests" in path.parts or "migrations" in path.parts:
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if not (
                isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "select_for_update"
            ):
                continue
            source = ast.unparse(node)
            locks_user_or_org = "User.objects" in source or "Organization.objects" in source
            if locks_user_or_org and "no_key=True" not in source:
                offenders.append(f"{path.relative_to(root)}:{node.lineno}")
    assert offenders == []
