"""System checks enforcing API access-control conventions (ADR-0012).

Run with every ``manage.py`` command (and in CI via ``make check``), so misconfiguration fails
before a server starts:

- ``core.E001``: a view uses ``PublicEndpoint`` but its URL name is not in
  ``settings.API_PUBLIC_ENDPOINTS`` (or it has no URL name).
- ``core.E002``: a view grants anonymous access with ``AllowAny`` or a subclass other than
  ``PublicEndpoint``.
- ``core.E003``: a view (or a ViewSet action) declares an empty ``permission_classes`` list, which
  DRF treats as "allow everyone".
- ``core.E004``: a DRF view does not include ``PublicAccessGuard`` (runtime enforcement).
- ``core.E005``: a URL name used by a DRF view is registered more than once.

Permissions decided dynamically (``get_permissions()`` overrides, custom classes whose
``has_permission`` returns True) cannot be proven statically; ``core.E004`` guarantees the
runtime guard covers them.
"""

from collections import defaultdict
from typing import Any

from django.conf import settings
from django.core.checks import CheckMessage, Error, Tags, register
from django.urls import URLPattern, get_resolver
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView

from apps.core.api.permissions import PublicAccessGuard, PublicEndpoint, iter_url_patterns


def _view_class(callback: Any) -> type[APIView] | None:
    view_class = getattr(callback, "cls", None)
    if isinstance(view_class, type) and issubclass(view_class, APIView):
        return view_class
    return None


def _declared_permission_classes(callback: Any, view_class: type[APIView]) -> list[Any]:
    initkwargs = getattr(callback, "initkwargs", None) or {}
    classes = initkwargs.get("permission_classes", view_class.permission_classes)
    return list(classes)


def find_public_endpoint_violations(urlconf: str | None = None) -> list[CheckMessage]:
    allowlist = set(getattr(settings, "API_PUBLIC_ENDPOINTS", ()))
    messages: list[CheckMessage] = []
    drf_names: dict[str, list[URLPattern]] = defaultdict(list)
    all_names: dict[str, int] = defaultdict(int)

    for name, pattern in iter_url_patterns(get_resolver(urlconf).url_patterns):
        if name:
            all_names[name] += 1
        view_class = _view_class(pattern.callback)
        if view_class is None:
            continue
        if name:
            drf_names[name].append(pattern)
        label = name or f"<unnamed route {pattern.pattern}>"

        if not issubclass(view_class, PublicAccessGuard):
            messages.append(
                Error(
                    f"DRF view {view_class.__name__} ({label}) does not use PublicAccessGuard.",
                    hint="Inherit from apps.core.api.views.AemsAPIView/AemsGenericAPIView/"
                    "AemsGenericViewSet or add the PublicAccessGuard mixin first.",
                    id="core.E004",
                )
            )

        classes = _declared_permission_classes(pattern.callback, view_class)
        if not classes:
            messages.append(
                Error(
                    f"Endpoint {label!r} declares no permission classes (DRF allows everyone).",
                    hint="Declare explicit permissions; use DenyAll or PublicEndpoint.",
                    id="core.E003",
                )
            )
            continue

        permissive = [c for c in classes if isinstance(c, type) and issubclass(c, AllowAny)]
        if any(not issubclass(c, PublicEndpoint) for c in permissive):
            messages.append(
                Error(
                    f"Endpoint {label!r} uses AllowAny (or a subclass other than PublicEndpoint).",
                    hint="Use PublicEndpoint and add the URL name to API_PUBLIC_ENDPOINTS.",
                    id="core.E002",
                )
            )
        if permissive and name not in allowlist:
            messages.append(
                Error(
                    f"Endpoint {label!r} allows anonymous access but is not listed in "
                    "settings.API_PUBLIC_ENDPOINTS.",
                    hint="Add its URL name to API_PUBLIC_ENDPOINTS or require authentication.",
                    id="core.E001",
                )
            )

    for name in sorted(drf_names):
        if all_names[name] > 1:
            messages.append(
                Error(
                    f"URL name {name!r} is registered {all_names[name]} times.",
                    hint="URL names used by API views must be unique; the public allowlist "
                    "and reverse() rely on them.",
                    id="core.E005",
                )
            )
    return messages


@register(Tags.security, Tags.urls)
def check_public_endpoints(app_configs: Any, **kwargs: Any) -> list[CheckMessage]:
    return find_public_endpoint_violations()
