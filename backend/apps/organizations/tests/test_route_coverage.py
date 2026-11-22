"""Route-coverage meta-test (ADR-0003 "mandatory tests", ADR-0015).

Every production API route is inspected. A new tenant or platform endpoint that skips the approved
infrastructure fails CI before it can be merged.
"""

from typing import Any, cast

import pytest
from django.conf import settings
from django.urls import URLPattern, get_resolver
from rest_framework.permissions import SAFE_METHODS
from rest_framework.views import APIView

from apps.core.api.permissions import iter_url_patterns
from apps.organizations.permissions import HasOrgPermission, IsPlatformAdministrator
from apps.organizations.scoping import ORGANIZATION_URL_KWARG, OrganizationScopedViewMixin

HANDLERS = ("get", "post", "put", "patch", "delete")
TENANT_PREFIX = "api/v1/organizations/"
PLATFORM_PREFIX = "api/v1/platform/"


def _routes() -> list[tuple[str, str | None, type[APIView]]]:
    """(route, url name, DRF view class) for every API route of the production URLconf."""
    found: list[tuple[str, str | None, type[APIView]]] = []

    def walk(patterns: list[Any], prefix: str) -> None:
        for entry in patterns:
            route = prefix + str(entry.pattern)
            if isinstance(entry, URLPattern):
                view_class = getattr(entry.callback, "view_class", None) or getattr(
                    entry.callback, "cls", None
                )
                if isinstance(view_class, type) and issubclass(view_class, APIView):
                    found.append((route, entry.name, view_class))
            else:
                walk(entry.url_patterns, route)

    walk(get_resolver(settings.ROOT_URLCONF).url_patterns, "")
    return found


ROUTES = _routes()
TENANT_ROUTES = [r for r in ROUTES if f"<uuid:{ORGANIZATION_URL_KWARG}>" in r[0]]
PLATFORM_ROUTES = [r for r in ROUTES if r[0].startswith(PLATFORM_PREFIX)]


def test_inventory_is_complete() -> None:
    assert {r[0] for r in TENANT_ROUTES} == {
        "api/v1/organizations/<uuid:org_id>/",
        "api/v1/organizations/<uuid:org_id>/me/",
    }
    assert {r[0] for r in PLATFORM_ROUTES} == {
        "api/v1/platform/organizations/",
        "api/v1/platform/organizations/<uuid:organization_id>/",
    }


def test_every_organization_route_other_than_the_list_is_tenant_scoped() -> None:
    for route, _name, _view in ROUTES:
        if route.startswith(TENANT_PREFIX) and route != TENANT_PREFIX:
            assert route.startswith(f"{TENANT_PREFIX}<uuid:{ORGANIZATION_URL_KWARG}>/"), route


@pytest.mark.parametrize(
    ("route", "name", "view"), TENANT_ROUTES, ids=[r[0] for r in TENANT_ROUTES]
)
def test_tenant_routes_use_the_approved_infrastructure(
    route: str, name: str | None, view: type[APIView]
) -> None:
    # Central resolution runs (the mixin precedes the base view in the MRO).
    assert issubclass(view, OrganizationScopedViewMixin), route
    resolved = cast(Any, view)
    assert resolved.check_permissions is OrganizationScopedViewMixin.check_permissions, route
    assert resolved.initial is OrganizationScopedViewMixin.initial, route
    # Default-deny organization authorization, nothing else.
    assert list(view.permission_classes) == [HasOrgPermission], route
    # Querysets only via get_scoped_queryset().
    assert getattr(view, "queryset", None) is None, route
    assert resolved.get_queryset is OrganizationScopedViewMixin.get_queryset, route
    # Every handler is declared: member reads only for safe methods, the rest by permission.
    member_actions = set(getattr(view, "member_actions", ()))
    required = getattr(view, "required_permissions", {})
    assert {a.upper() for a in member_actions} <= set(SAFE_METHODS), route
    for handler in HANDLERS:
        if hasattr(view, handler):
            assert handler in member_actions or required.get(handler), (route, handler)
    # Never public.
    assert name is None or not str(name).endswith(tuple(settings.API_PUBLIC_ENDPOINTS))


@pytest.mark.parametrize(
    ("route", "name", "view"), PLATFORM_ROUTES, ids=[r[0] for r in PLATFORM_ROUTES]
)
def test_platform_routes_require_platform_administrators(
    route: str, name: str | None, view: type[APIView]
) -> None:
    assert list(view.permission_classes) == [IsPlatformAdministrator], route
    assert not issubclass(view, OrganizationScopedViewMixin), route


def test_no_organization_route_is_public() -> None:
    public = set(settings.API_PUBLIC_ENDPOINTS)
    names = {name for name, _ in iter_url_patterns(get_resolver().url_patterns) if name}
    organization_names = {n for n in names if ":organizations:" in n or ":platform:" in n}
    assert organization_names
    assert not organization_names & public
