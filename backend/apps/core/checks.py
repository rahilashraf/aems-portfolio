"""System checks enforcing the explicit public-endpoint allowlist.

- ``core.E001``: a DRF view grants anonymous access (``AllowAny`` or a subclass) but its URL name
  is not in ``settings.API_PUBLIC_ENDPOINTS``.
- ``core.E002``: a DRF view uses bare ``AllowAny`` instead of the explicit ``PublicEndpoint``.

Runs with every ``manage.py`` command (and in CI), so a new unauthenticated endpoint cannot be
added accidentally.
"""

from collections.abc import Iterator
from typing import Any

from django.conf import settings
from django.core.checks import CheckMessage, Error, Tags, register
from django.urls import URLPattern, URLResolver, get_resolver
from rest_framework.permissions import AllowAny

from apps.core.api.permissions import PublicEndpoint


def _iter_patterns(
    patterns: list[Any], namespace: str | None = None
) -> Iterator[tuple[str | None, URLPattern]]:
    for entry in patterns:
        if isinstance(entry, URLResolver):
            child_ns = namespace
            if entry.namespace:
                child_ns = f"{namespace}:{entry.namespace}" if namespace else entry.namespace
            yield from _iter_patterns(entry.url_patterns, child_ns)
        elif isinstance(entry, URLPattern):
            name = None
            if entry.name:
                name = f"{namespace}:{entry.name}" if namespace else entry.name
            yield name, entry


def _permission_classes(callback: Any) -> list[type[Any]] | None:
    view_class = getattr(callback, "cls", None)
    if view_class is None:  # not a DRF view
        return None
    initkwargs = getattr(callback, "initkwargs", {}) or {}
    classes = initkwargs.get("permission_classes", getattr(view_class, "permission_classes", ()))
    return [c for c in classes if isinstance(c, type)]


def find_public_endpoint_violations(urlconf: str | None = None) -> list[CheckMessage]:
    allowlist = set(getattr(settings, "API_PUBLIC_ENDPOINTS", ()))
    messages: list[CheckMessage] = []
    for name, pattern in _iter_patterns(get_resolver(urlconf).url_patterns):
        classes = _permission_classes(pattern.callback)
        if not classes:
            continue
        public = [c for c in classes if issubclass(c, AllowAny)]
        if not public:
            continue
        label = name or str(pattern.pattern)
        if any(not issubclass(c, PublicEndpoint) for c in public):
            messages.append(
                Error(
                    f"Endpoint {label!r} uses AllowAny; use PublicEndpoint and allowlist it.",
                    id="core.E002",
                )
            )
        if name not in allowlist:
            messages.append(
                Error(
                    f"Endpoint {label!r} allows anonymous access but is not listed in "
                    "settings.API_PUBLIC_ENDPOINTS.",
                    hint="Add its URL name to API_PUBLIC_ENDPOINTS or require authentication.",
                    id="core.E001",
                )
            )
    return messages


@register(Tags.security, Tags.urls)
def check_public_endpoints(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    return find_public_endpoint_violations()
