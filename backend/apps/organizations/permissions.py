"""Authorization for organization APIs (Batch 4; ADR-0015).

Batch 4 has no RBAC engine. Authorization is therefore:

- **Platform administration**: :class:`IsPlatformAdministrator` - an active staff account that
  also holds the matching Django model permission (``organizations.view_organization``,
  ``add_organization``, ``change_organization``). Being staff alone is not enough, and platform
  status never implies tenant membership.
- **Tenant endpoints**: ``OrganizationScopedViewMixin`` first resolves an active membership in an
  active organization (404 otherwise), then :class:`HasOrgPermission` applies per-action
  declarations with default deny. Membership alone authorizes only declared read-only actions; in
  Batch 4 **every** permission-gated action is denied because there are no roles to grant
  permissions. Batch 6 replaces :func:`membership_has_permissions` with the RBAC engine; views do
  not change.
"""

from collections.abc import Iterable
from typing import Any

from rest_framework.permissions import SAFE_METHODS, BasePermission
from rest_framework.request import Request

from .models import Membership

_PLATFORM_PERMISSIONS = {
    "GET": "organizations.view_organization",
    "HEAD": "organizations.view_organization",
    "OPTIONS": "organizations.view_organization",
    "POST": "organizations.add_organization",
    "PATCH": "organizations.change_organization",
}


class IsPlatformAdministrator(BasePermission):
    message = "You do not have permission to perform this action."

    def has_permission(self, request: Request, view: Any) -> bool:
        user = request.user
        if not (getattr(user, "is_active", False) and getattr(user, "is_staff", False)):
            return False
        required = _PLATFORM_PERMISSIONS.get(request.method or "")
        return required is not None and user.has_perm(required)


def _membership(request: Request) -> Membership | None:
    membership = getattr(request, "membership", None)
    return membership if isinstance(membership, Membership) else None


def membership_has_permissions(membership: Membership, permissions: Iterable[str]) -> bool:
    """Batch 6 integration point: evaluate organization permissions for a membership.

    There are no roles before Batch 6, so no permission can be held: fail closed.
    """
    return False


class HasOrgPermission(BasePermission):
    """Tenant authorization with per-action declarations and default deny.

    The key of an action is ``view.action`` (ViewSets) or the lower-case HTTP method (APIViews).

    - ``member_actions``: read-only actions any active member may perform (for example viewing the
      organization profile). Honoured **only for safe methods**, so membership alone can never
      authorize a write.
    - ``required_permissions``: ``{"patch": ("organization.update",)}``. Every listed permission is
      required. In Batch 4 none can be held (no roles), so these actions fail closed.
    - Anything not declared is denied.
    """

    message = "You do not have permission to perform this action."

    def has_permission(self, request: Request, view: Any) -> bool:
        membership = _membership(request)
        if membership is None:
            return False
        key = getattr(view, "action", None) or (request.method or "").lower()
        if request.method in SAFE_METHODS and key in getattr(view, "member_actions", ()):
            return True
        declared: dict[str, Iterable[str]] = getattr(view, "required_permissions", {})
        required = tuple(declared.get(key, ()))
        if not required:
            return False
        return membership_has_permissions(membership, required)
