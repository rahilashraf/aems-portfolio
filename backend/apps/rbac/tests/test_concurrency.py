"""Concurrency regression tests on real PostgreSQL transactions (plan §6.5, ADR-0017).

Threads are released together by a barrier; each uses its own database connection. A deadlock
would surface as ``DatabaseError`` ("deadlock detected") and fail the test.
"""

import threading
import time
from collections.abc import Callable
from typing import Any

import pytest
from django.db import DatabaseError, connections, transaction

from apps.accounts.models import User
from apps.accounts.services import deactivate_user
from apps.organizations.models import Membership, MembershipStatus, Organization
from apps.rbac import services
from apps.rbac.exceptions import LastOwnerError, RbacForbiddenError
from apps.rbac.models import MembershipRole, Role, SystemRole

from .conftest import custom_role, member, role

pytestmark = pytest.mark.django_db(transaction=True)

ALLOWED_FAILURES = (RbacForbiddenError, LastOwnerError)


def run_together(*calls: Callable[[], Any]) -> list[Any]:
    """Run ``calls`` concurrently; return each result or the exception it raised."""
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
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
        assert not thread.is_alive(), "a worker hung (lock wait or deadlock)"
    return results


def outcomes(results: list[Any]) -> tuple[int, list[BaseException]]:
    failures = [r for r in results if isinstance(r, BaseException)]
    unexpected = [f for f in failures if not isinstance(f, ALLOWED_FAILURES)]
    assert unexpected == [], unexpected
    return len(results) - len(failures), failures


def active_owners(organization: Organization) -> set[Any]:
    return set(
        MembershipRole.objects.filter(
            organization=organization,
            role__system_key=SystemRole.OWNER,
            membership__status=MembershipStatus.ACTIVE,
            membership__user__is_active=True,
        ).values_list("membership__user_id", flat=True)
    )


@pytest.fixture
def owners(make_org: Callable[..., Organization], make_user: Callable[..., User]) -> Any:
    """Organization with exactly two active Owners and nothing else."""
    organization = make_org(slug="duo")
    first, second = make_user("o1@example.org"), make_user("o2@example.org")
    owner_role = role(organization, SystemRole.OWNER)
    return (
        organization,
        member(organization, first, owner_role),
        member(organization, second, owner_role),
    )


def test_co_owners_removing_each_others_owner_role(owners: Any) -> None:
    organization, first, second = owners
    for _ in range(3):
        results = run_together(
            lambda: services.replace_membership_roles(
                actor=first.user, organization=organization, membership_id=second.pk, role_ids=[]
            ),
            lambda: services.replace_membership_roles(
                actor=second.user, organization=organization, membership_id=first.pk, role_ids=[]
            ),
        )
        succeeded, failures = outcomes(results)
        assert (succeeded, len(failures)) == (1, 1)
        assert len(active_owners(organization)) == 1
        # Restore two Owners for the next round.
        owner_role = role(organization, SystemRole.OWNER)
        for m in (first, second):
            MembershipRole.objects.get_or_create(
                organization=organization, membership=m, role=owner_role
            )


def test_co_owners_relinquishing_simultaneously(owners: Any) -> None:
    organization, first, second = owners
    results = run_together(
        *(
            (
                lambda m=m: services.replace_membership_roles(
                    actor=m.user, organization=organization, membership_id=m.pk, role_ids=[]
                )
            )
            for m in (first, second)
        )
    )
    succeeded, failures = outcomes(results)
    assert succeeded == 1
    assert [type(f) for f in failures] == [LastOwnerError]
    assert len(active_owners(organization)) == 1


def test_co_owners_suspending_each_other(owners: Any) -> None:
    organization, first, second = owners
    results = run_together(
        lambda: services.update_membership_status(
            actor=first.user, organization=organization, membership_id=second.pk, status="suspended"
        ),
        lambda: services.update_membership_status(
            actor=second.user, organization=organization, membership_id=first.pk, status="suspended"
        ),
    )
    succeeded, failures = outcomes(results)
    assert (succeeded, len(failures)) == (1, 1)  # the loser was suspended before its turn
    assert len(active_owners(organization)) == 1
    assert (
        Membership.objects.filter(
            organization=organization, status=MembershipStatus.SUSPENDED
        ).count()
        == 1
    )


def test_membership_removal_racing_owner_relinquishment(owners: Any) -> None:
    organization, first, second = owners
    results = run_together(
        lambda: services.remove_membership(
            actor=first.user, organization=organization, membership_id=second.pk
        ),
        lambda: services.replace_membership_roles(
            actor=first.user, organization=organization, membership_id=first.pk, role_ids=[]
        ),
    )
    succeeded, _failures = outcomes(results)
    assert succeeded == 1
    assert len(active_owners(organization)) == 1


def test_concurrent_global_deactivation_across_organizations(
    make_org: Callable[..., Organization], make_user: Callable[..., User]
) -> None:
    """Two users co-own two organizations; deactivating both at once must fail for one."""
    first, second = make_user("u1@example.org"), make_user("u2@example.org")
    organizations = [make_org(slug="north"), make_org(slug="south")]
    for organization in organizations:
        owner_role = role(organization, SystemRole.OWNER)
        member(organization, first, owner_role)
        member(organization, second, owner_role)
    results = run_together(lambda: deactivate_user(first), lambda: deactivate_user(second))
    succeeded, failures = outcomes(results)
    assert succeeded == 1
    [error] = failures
    assert isinstance(error, LastOwnerError)
    assert error.organization_ids == tuple(sorted(str(o.pk) for o in organizations))
    assert User.objects.filter(pk__in=[first.pk, second.pk], is_active=True).count() == 1
    for organization in organizations:
        assert len(active_owners(organization)) == 1


def test_mixed_operations_do_not_deadlock(
    make_org: Callable[..., Organization], make_user: Callable[..., User]
) -> None:
    """Deactivation (user → organizations) racing membership and role changes in both orgs."""
    users = {name: make_user(f"{name}@example.org") for name in ("a", "b", "c", "x", "y")}
    north, south = make_org(slug="north"), make_org(slug="south")
    memberships = {}
    for organization in (north, south):
        owner_role = role(organization, SystemRole.OWNER)
        for name in ("a", "b", "c"):
            memberships[(organization.slug, name)] = member(organization, users[name], owner_role)
        for name in ("x", "y"):
            memberships[(organization.slug, name)] = member(organization, users[name])
    calls = [
        lambda: deactivate_user(users["a"]),
        lambda: services.update_membership_status(
            actor=users["b"],
            organization=south,
            membership_id=memberships[("south", "x")].pk,
            status="suspended",
        ),
        lambda: services.remove_membership(
            actor=users["c"], organization=north, membership_id=memberships[("north", "y")].pk
        ),
        lambda: services.replace_membership_roles(
            actor=users["b"],
            organization=north,
            membership_id=memberships[("north", "x")].pk,
            role_ids=[role(north, SystemRole.MEMBER).pk],
        ),
        lambda: services.create_role(actor=users["c"], organization=south, name="Late"),
        lambda: deactivate_user(users["x"]),
    ]
    for _ in range(3):
        # Later rounds hit already-applied changes (404, name taken): only database errors such
        # as "deadlock detected" or a hung worker fail this test.
        for result in run_together(*calls):
            assert not isinstance(result, DatabaseError), result
    for organization in (north, south):
        assert active_owners(organization)


def _hold(call: Callable[[], Any], started: threading.Event, release: threading.Event) -> Any:
    """Run ``call`` inside an outer transaction and keep it open until ``release``."""
    try:
        with transaction.atomic():
            result = call()
            started.set()
            assert release.wait(timeout=20)
        return result
    finally:
        connections.close_all()


def _race_with_held_change(
    holder: Callable[[], Any], contender: Callable[[], Any]
) -> tuple[Any, Any, bool]:
    """``holder`` commits while ``contender`` waits on the organization lock."""
    started, release = threading.Event(), threading.Event()
    results: dict[str, Any] = {}

    def run(name: str, call: Callable[[], Any]) -> None:
        try:
            results[name] = call()
        except BaseException as exc:
            results[name] = exc
        finally:
            connections.close_all()

    first = threading.Thread(target=run, args=("holder", lambda: _hold(holder, started, release)))
    first.start()
    assert started.wait(timeout=20)
    second = threading.Thread(target=run, args=("contender", contender))
    second.start()
    time.sleep(0.5)
    blocked = second.is_alive()  # waiting for the organization lock
    release.set()
    first.join(timeout=30)
    second.join(timeout=30)
    return results["holder"], results["contender"], blocked


def test_revoked_roles_manage_cannot_be_used_by_an_in_flight_request(
    make_org: Callable[..., Organization], make_user: Callable[..., User]
) -> None:
    organization = make_org(slug="stale")
    owner = member(organization, make_user("own@example.org"), role(organization, SystemRole.OWNER))
    admin = member(organization, make_user("adm@example.org"), role(organization, SystemRole.ADMIN))
    admin_role = role(organization, SystemRole.ADMIN)
    remaining = sorted(
        set(admin_role.permissions.values_list("code", flat=True)) - {"roles.manage"}
    )
    holder, contender, blocked = _race_with_held_change(
        lambda: services.update_role(
            actor=owner.user,
            organization=organization,
            role_id=admin_role.pk,
            changes={"permissions": remaining},
        ),
        lambda: services.create_role(actor=admin.user, organization=organization, name="Sneaky"),
    )
    assert blocked
    assert isinstance(holder, Role)
    assert isinstance(contender, RbacForbiddenError)
    assert not Role.objects.filter(organization=organization, name="Sneaky").exists()


def test_permission_removed_from_the_actors_role_blocks_delegation(
    make_org: Callable[..., Organization], make_user: Callable[..., User]
) -> None:
    """The actor tries to grant audit.view while its own role loses audit.view."""
    organization = make_org(slug="shift")
    owner = member(organization, make_user("own@example.org"), role(organization, SystemRole.OWNER))
    admin = member(organization, make_user("adm@example.org"), role(organization, SystemRole.ADMIN))
    readers = custom_role(organization, "Readers", "organization.view")
    admin_role = role(organization, SystemRole.ADMIN)
    remaining = sorted(set(admin_role.permissions.values_list("code", flat=True)) - {"audit.view"})
    _holder, contender, blocked = _race_with_held_change(
        lambda: services.update_role(
            actor=owner.user,
            organization=organization,
            role_id=admin_role.pk,
            changes={"permissions": remaining},
        ),
        lambda: services.update_role(
            actor=admin.user,
            organization=organization,
            role_id=readers.pk,
            changes={"permissions": ["organization.view", "audit.view"]},
        ),
    )
    assert blocked
    assert isinstance(contender, RbacForbiddenError)
    assert set(readers.permissions.values_list("code", flat=True)) == {"organization.view"}


def test_actor_suspended_while_their_request_waits(
    make_org: Callable[..., Organization], make_user: Callable[..., User]
) -> None:
    organization = make_org(slug="gone")
    owner = member(organization, make_user("own@example.org"), role(organization, SystemRole.OWNER))
    admin = member(organization, make_user("adm@example.org"), role(organization, SystemRole.ADMIN))
    target = member(organization, make_user("t@example.org"))
    _holder, contender, blocked = _race_with_held_change(
        lambda: services.update_membership_status(
            actor=owner.user, organization=organization, membership_id=admin.pk, status="suspended"
        ),
        lambda: services.remove_membership(
            actor=admin.user, organization=organization, membership_id=target.pk
        ),
    )
    assert blocked
    assert isinstance(contender, RbacForbiddenError)
    assert Membership.objects.filter(pk=target.pk).exists()


def test_organizations_do_not_block_each_other(
    make_org: Callable[..., Organization], make_user: Callable[..., User]
) -> None:
    north, south = make_org(slug="north"), make_org(slug="south")
    north_owner = member(north, make_user("n@example.org"), role(north, SystemRole.OWNER))
    south_owner = member(south, make_user("s@example.org"), role(south, SystemRole.OWNER))
    holder, contender, blocked = _race_with_held_change(
        lambda: services.create_role(actor=north_owner.user, organization=north, name="Held"),
        lambda: services.create_role(actor=south_owner.user, organization=south, name="Free"),
    )
    assert not blocked  # different organization row: no waiting
    assert isinstance(holder, Role)
    assert isinstance(contender, Role)
    # A role of one organization cannot be targeted through another.
    from rest_framework.exceptions import NotFound  # noqa: PLC0415

    with pytest.raises(NotFound):
        services.update_role(
            actor=south_owner.user,
            organization=south,
            role_id=holder.pk,
            changes={"name": "Hijacked"},
        )
    holder.refresh_from_db()
    assert holder.name == "Held"
