"""Authorization for organization APIs (ADR-0015, ADR-0017).

- **Platform administration**: :class:`IsPlatformAdministrator` - an active staff account that
  also holds the matching Django model permission (``organizations.view_organization``,
  ``add_organization``, ``change_organization``). Being staff alone is not enough, and platform
  status never implies tenant membership.
- **Tenant endpoints**: ``OrganizationScopedViewMixin`` first resolves an active membership in an
  active organization (404 otherwise), then :class:`HasOrgPermission` applies per-action
  declarations with default deny. Membership alone authorizes only declared read-only actions;
  every other action requires organization permissions, evaluated by the RBAC engine
  (:mod:`apps.rbac.engine`, Batch 6) from the membership's roles in that organization.
"""

from collections.abc import Iterable
from typing import Any

from rest_framework.permissions import SAFE_METHODS, BasePermission
from rest_framework.request import Request

from apps.rbac import engine

from .models import Membership

_PLATFORM_PERMISSIONS = {
    "GET": "organizations.view_organization",
    "HEAD": "organizations.view_organization",
    "OPTIONS": "organizations.view_organization",
    "POST": "organizations.add_organization",
    "PATCH": "organizations.change_organization",
}


class IsPlatformAdministrator(BasePermission):
    """Active staff holding the Django model permission mapped to the request method.

    Subclasses for other platform resources override :attr:`method_permissions`.
    """

    message = "You do not have permission to perform this action."
    method_permissions: dict[str, str] = _PLATFORM_PERMISSIONS

    def has_permission(self, request: Request, view: Any) -> bool:
        user = request.user
        if not (getattr(user, "is_active", False) and getattr(user, "is_staff", False)):
            return False
        required = self.method_permissions.get(request.method or "")
        return required is not None and user.has_perm(required)


def _membership(request: Request) -> Membership | None:
    membership = getattr(request, "membership", None)
    return membership if isinstance(membership, Membership) else None


def membership_has_permissions(membership: Membership, permissions: Iterable[str]) -> bool:
    """Evaluate organization permissions for the request's membership (RBAC engine).

    Unknown or deprecated codes are never held. The result is cached on the membership instance,
    which the tenant API resolves anew for every request.
    """
    return engine.has_permissions(membership, permissions)


class HasOrgPermission(BasePermission):
    """Tenant authorization with per-action declarations and default deny.

    The key of an action is ``view.action`` (ViewSets) or the lower-case HTTP method (APIViews).

    - ``member_actions``: read-only actions any active member may perform (for example reading
      their own membership at ``me/``). Honoured **only for safe methods**, so membership alone
      can never authorize a write.
    - ``required_permissions``: ``{"patch": ("organization.update",)}``. Every listed permission is
      required, evaluated for this organization only.
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
