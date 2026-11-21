"""API permission primitives.

The project default (``REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"]``) is :class:`DenyAll`: a view
that does not explicitly declare permissions can never be reached. Batch 3 replaces the default
with authenticated access once the identity model exists.

Endpoints that must be reachable without authentication use :class:`PublicEndpoint` **and** must
be listed by URL name in ``settings.API_PUBLIC_ENDPOINTS``; the ``core.E001``/``core.E002``
system checks (see :mod:`apps.core.checks`) fail startup otherwise.
"""

from typing import Any

from rest_framework.permissions import AllowAny, BasePermission
from rest_framework.request import Request


class DenyAll(BasePermission):
    """Deny every request. The project-wide default."""

    message = "You do not have permission to perform this action."

    def has_permission(self, request: Request, view: Any) -> bool:
        return False

    def has_object_permission(self, request: Request, view: Any, obj: Any) -> bool:
        return False


class PublicEndpoint(AllowAny):
    """Allow unauthenticated access. Only valid on allowlisted endpoints."""
