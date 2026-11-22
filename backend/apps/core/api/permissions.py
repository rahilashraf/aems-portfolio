"""API access control primitives and the public-endpoint allowlist (ADR-0012).

Defence in depth, all fail-closed:

1. **Deny by default.** ``REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"]`` is :class:`DenyAll`.
2. **Explicit public endpoints.** Unauthenticated access is only possible on endpoints whose URL
   name is listed in ``settings.API_PUBLIC_ENDPOINTS`` and that use :class:`PublicEndpoint`.
3. **Runtime allowlist check in PublicEndpoint.** It grants access only if the resolved URL name
   is allowlisted, that name maps to exactly one route, and the request was resolved to that
   route (a duplicate URL name can never "borrow" an allowlist entry).
4. **Runtime guard** (:class:`PublicAccessGuard`, required on every DRF view by system check
   ``core.E004``). After DRF's own permission checks pass, any request that is not
   authenticated is refused unless the endpoint passes the same allowlist test. This catches empty
   ``permission_classes``, overridden ``get_permissions()``, ViewSet action-specific permissions
   and custom permissive classes, none of which can be fully verified statically.
5. **Static system checks** (:mod:`apps.core.checks`) reject misconfiguration at startup and in CI.

Transition to Batch 3: once authentication classes exist, the default permission becomes
"authenticated" (with :class:`DenyAll` still available for explicit lockdown). The guard keeps
applying to unauthenticated requests only, so authenticated access is governed by the normal
permission classes (and, from Batch 6, organization RBAC). Unauthenticated requests to
non-allowlisted endpoints will then raise ``NotAuthenticated`` (401 with ``WWW-Authenticate``)
instead of 403.
"""

from collections.abc import Callable, Iterator
from functools import lru_cache
from typing import Any

import structlog
from django.conf import settings
from django.urls import URLPattern, URLResolver, get_resolver
from rest_framework.permissions import AllowAny, BasePermission
from rest_framework.request import Request

logger = structlog.get_logger(__name__)


class DenyAll(BasePermission):
    """Deny every request. The project-wide default."""

    message = "You do not have permission to perform this action."

    def has_permission(self, request: Request, view: Any) -> bool:
        return False

    def has_object_permission(self, request: Request, view: Any, obj: Any) -> bool:
        return False


# --------------------------------------------------------------------------- URL introspection
def iter_url_patterns(
    patterns: list[Any], namespace: str | None = None
) -> Iterator[tuple[str | None, URLPattern]]:
    """Yield ``(fully_qualified_name, pattern)`` for every URL pattern, recursively."""
    for entry in patterns:
        if isinstance(entry, URLResolver):
            child_ns = namespace
            if entry.namespace:
                child_ns = f"{namespace}:{entry.namespace}" if namespace else entry.namespace
            yield from iter_url_patterns(entry.url_patterns, child_ns)
        elif isinstance(entry, URLPattern):
            name = None
            if entry.name:
                name = f"{namespace}:{entry.name}" if namespace else entry.name
            yield name, entry


@lru_cache(maxsize=16)
def named_callbacks(urlconf: str) -> dict[str, tuple[Callable[..., Any], ...]]:
    """Map each fully qualified URL name to the view callbacks registered under it."""
    mapping: dict[str, list[Callable[..., Any]]] = {}
    for name, pattern in iter_url_patterns(get_resolver(urlconf).url_patterns):
        if name:
            mapping.setdefault(name, []).append(pattern.callback)
    return {name: tuple(callbacks) for name, callbacks in mapping.items()}


def _request_urlconf(request: Any) -> str:
    urlconf = getattr(request, "urlconf", None) or settings.ROOT_URLCONF
    return urlconf if isinstance(urlconf, str) else str(settings.ROOT_URLCONF)


def is_allowlisted_public_request(request: Any) -> bool:
    """True only if the request resolved to the one route registered under an allowlisted name."""
    match = getattr(request, "resolver_match", None)
    if match is None or not match.url_name:
        return False
    view_name = match.view_name
    if view_name not in set(settings.API_PUBLIC_ENDPOINTS):
        return False
    callbacks = named_callbacks(_request_urlconf(request)).get(view_name, ())
    return len(callbacks) == 1 and callbacks[0] is match.func


def is_authenticated(user: Any) -> bool:
    return bool(user is not None and getattr(user, "is_authenticated", False))


# --------------------------------------------------------------------------- permissions
class PublicEndpoint(AllowAny):
    """Allow unauthenticated access, but only on allowlisted, uniquely named routes."""

    message = "You do not have permission to perform this action."

    def has_permission(self, request: Request, view: Any) -> bool:
        if is_allowlisted_public_request(request):
            return True
        logger.error(
            "security.public_endpoint_not_allowlisted",
            view=type(view).__name__,
            view_name=getattr(getattr(request, "resolver_match", None), "view_name", None),
        )
        return False


class PublicAccessGuard:
    """Mixin for every DRF view: refuse unauthenticated access to non-allowlisted endpoints.

    Runs after DRF's own permission checks, whatever produced them (class attributes,
    ``get_permissions()`` overrides, ViewSet actions or custom permission classes).
    """

    def check_permissions(self, request: Request) -> None:
        super().check_permissions(request)  # type: ignore[misc]
        if is_authenticated(getattr(request, "user", None)):
            return
        if is_allowlisted_public_request(request):
            return
        logger.error(
            "security.public_access_blocked",
            view=type(self).__name__,
            view_name=getattr(getattr(request, "resolver_match", None), "view_name", None),
        )
        self.permission_denied(request)  # type: ignore[attr-defined]
