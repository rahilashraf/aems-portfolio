"""Read paths for organizations and memberships (ADR-0015).

The tenant API never queries tenant tables directly: it resolves one membership here and then uses
``Model.objects.for_organization(...)``. The functions below are the only **cross-tenant** reads,
each deliberately narrow:

- :func:`resolve_active_membership` - one membership of the caller, by URL organization id.
- :func:`memberships_for_user` - the caller's own memberships ("my organizations").
- :func:`organizations_for_platform` - platform administration (all organizations).
"""

import uuid
from typing import Any

from django.db.models import QuerySet

from .models import Membership, MembershipStatus, Organization, OrganizationStatus


def resolve_active_membership(user: Any, organization_id: Any) -> Membership | None:
    """The caller's active membership in an active organization, or None.

    One query whatever the reason for failure (unknown organization, not a member, suspended
    membership, provisioning or suspended organization, inactive user), so callers can answer with
    the same 404 for all of them.
    """
    if not getattr(user, "is_authenticated", False) or not getattr(user, "is_active", False):
        return None
    try:
        organization_uuid = uuid.UUID(str(organization_id))
    except (TypeError, ValueError):
        return None
    return (
        Membership.objects.select_related("organization")
        .filter(
            organization_id=organization_uuid,
            user=user,
            status=MembershipStatus.ACTIVE,
            organization__status=OrganizationStatus.ACTIVE,
        )
        .first()
    )


def memberships_for_user(user: Any) -> QuerySet[Membership]:
    """The caller's active memberships in active organizations (``GET /organizations/``).

    Provisioning and suspended organizations, and suspended memberships, are excluded: they are not
    usable through the tenant API, so listing them would only disclose state.
    """
    if not getattr(user, "is_active", False):
        return Membership.objects.none()
    return Membership.objects.select_related("organization").filter(
        user=user,
        status=MembershipStatus.ACTIVE,
        organization__status=OrganizationStatus.ACTIVE,
    )


def organizations_for_platform() -> QuerySet[Organization]:
    return Organization.objects.select_related("created_by")
