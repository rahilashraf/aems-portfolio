"""Organization-scoped permission evaluation (plan §6.2, ADR-0017).

Effective permissions of a membership are the union of the permissions of its roles. Holding the
organization's Owner role means holding every **active** catalog permission, evaluated from the
registry at call time, so a newly registered permission is included automatically.

One query computes the set. It counts only when, at that moment:

- the user account is active;
- the membership is active;
- the organization is active;
- each role belongs to the membership's organization (also guaranteed by composite foreign keys).

Codes that are not registered, or deprecated (in the registry or in the database), are discarded:
a stale database row grants nothing.
Django's global model permissions and ``is_staff``/``is_superuser`` play no part.

Caching: :func:`effective_permissions` memoizes the result on the membership **instance**. The
tenant API resolves a new instance on every request, so the cache lives for one request only.
Authorization-sensitive services never use it: they call :func:`fresh_permissions` inside their
locked transaction (stale-permission protection, plan §6.4).
"""

from collections.abc import Iterable
from typing import Any

from apps.organizations.models import Membership, MembershipStatus, OrganizationStatus

from .models import MembershipRole, SystemRole
from .registry import registry

_CACHE_ATTR = "_rbac_effective_permissions"


def fresh_permissions(membership_id: Any) -> tuple[frozenset[str], bool]:
    """``(effective permissions, is_owner)`` from current database state. Never cached."""
    rows = MembershipRole.objects.filter(
        membership_id=membership_id,
        membership__status=MembershipStatus.ACTIVE,
        membership__user__is_active=True,
        membership__organization__status=OrganizationStatus.ACTIVE,
    ).values_list(
        "role__system_key",
        "role__permissions__code",
        "role__permissions__is_deprecated",
        "role__organization_id",
        "membership__organization_id",
    )
    codes: set[str] = set()
    is_owner = False
    for system_key, code, deprecated, role_org, membership_org in rows:
        if role_org != membership_org:  # pragma: no cover - prevented by composite foreign keys
            continue
        if system_key == SystemRole.OWNER:
            is_owner = True
        if code is not None and not deprecated:
            codes.add(code)
    if is_owner:
        return registry.active_codes(), True
    return frozenset(c for c in codes if registry.is_active(c)), False


def effective_permissions(membership: Membership) -> frozenset[str]:
    cached: frozenset[str] | None = getattr(membership, _CACHE_ATTR, None)
    if cached is None:
        cached, _ = fresh_permissions(membership.pk)
        setattr(membership, _CACHE_ATTR, cached)
    return cached


def has_permissions(membership: Membership, required: Iterable[str]) -> bool:
    """True only if every required code is an active catalog permission held by the membership."""
    required = tuple(required)
    if not required or any(not registry.is_active(code) for code in required):
        return False
    return set(required) <= effective_permissions(membership)
