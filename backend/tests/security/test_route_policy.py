"""Complete route inventory and authorization policy (plan §5.2 layer 7, §8, ADR-0012, ADR-0019).

Every route of the production URLconf (DRF and plain Django) must appear in :data:`POLICY` with an
explicit classification; a new route that is not classified fails CI. Each classification is then
verified statically (permission classes, allowlist, tenant infrastructure) and live (anonymous and
unprivileged requests against every route).

Complements ``apps/organizations/tests/test_route_coverage.py``, which checks the tenant routes'
per-handler declarations.
"""

import re
import uuid
from collections.abc import Callable
from typing import Any, cast

import pytest
from django.conf import settings
from django.test import Client
from django.urls import URLPattern, URLResolver, get_resolver
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from apps.core.api.permissions import PublicAccessGuard, PublicEndpoint, iter_url_patterns
from apps.organizations.api.invitation_views import PublicInvitationView
from apps.organizations.permissions import HasOrgPermission, IsPlatformAdministrator
from apps.organizations.scoping import OrganizationScopedViewMixin
from apps.organizations.tests.conftest import Api
from apps.rbac.models import Permission as CatalogPermission
from apps.rbac.registry import registry
from apps.rbac.tests.conftest import Team

PUBLIC = "public"  # allowlisted, no credentials needed
TOKEN = "public-token"  # allowlisted, scoped by an unguessable token in the path
AUTHENTICATED = "authenticated"  # any active, signed-in account (own data only)
TENANT = "tenant"  # active membership + organization permission
PLATFORM = "platform"  # active staff + explicit Django model permission
DOCS = "docs"  # OpenAPI documents: public but disabled unless API_DOCS_ENABLED
HEALTH = "health"  # plain Django probes, no data
ADMIN = "admin"  # Django admin (staff session, own login)

POLICY: dict[str, str] = {
    "health/live/": HEALTH,
    "health/ready/": HEALTH,
    "api/schema/": DOCS,
    "api/docs/": DOCS,
    "api/redoc/": DOCS,
    "api/v1/": PUBLIC,
    "api/v1/auth/csrf/": PUBLIC,
    "api/v1/auth/login/": PUBLIC,
    "api/v1/auth/token/refresh/": PUBLIC,
    "api/v1/auth/logout/": PUBLIC,
    "api/v1/auth/password/reset/": PUBLIC,
    "api/v1/auth/password/reset/confirm/": PUBLIC,
    "api/v1/auth/me/": AUTHENTICATED,
    "api/v1/auth/password/change/": AUTHENTICATED,
    "api/v1/auth/sessions/": AUTHENTICATED,
    "api/v1/auth/sessions/revoke-others/": AUTHENTICATED,
    "api/v1/auth/sessions/<uuid:session_id>/": AUTHENTICATED,
    "api/v1/organizations/": AUTHENTICATED,
    "api/v1/invitations/<str:token>/": TOKEN,
    "api/v1/invitations/<str:token>/accept/": TOKEN,
    "api/v1/organizations/<uuid:org_id>/": TENANT,
    "api/v1/organizations/<uuid:org_id>/me/": TENANT,
    "api/v1/organizations/<uuid:org_id>/audit-logs/": TENANT,
    "api/v1/organizations/<uuid:org_id>/members/": TENANT,
    "api/v1/organizations/<uuid:org_id>/members/<uuid:membership_id>/": TENANT,
    "api/v1/organizations/<uuid:org_id>/members/<uuid:membership_id>/roles/": TENANT,
    "api/v1/organizations/<uuid:org_id>/roles/": TENANT,
    "api/v1/organizations/<uuid:org_id>/roles/<uuid:role_id>/": TENANT,
    "api/v1/organizations/<uuid:org_id>/permissions/": TENANT,
    "api/v1/organizations/<uuid:org_id>/invitations/": TENANT,
    "api/v1/organizations/<uuid:org_id>/invitations/<uuid:invitation_id>/revoke/": TENANT,
    "api/v1/platform/organizations/": PLATFORM,
    "api/v1/platform/organizations/<uuid:organization_id>/": PLATFORM,
    "api/v1/platform/organizations/<uuid:organization_id>/initial-owner-invitation/": PLATFORM,
    "api/v1/platform/organizations/<uuid:organization_id>/initial-owner-invitation/revoke/": (
        PLATFORM
    ),
    "api/v1/platform/audit-logs/": PLATFORM,
}
ADMIN_PREFIX = settings.ADMIN_URL
HANDLERS = ("get", "post", "put", "patch", "delete")


def _all_routes() -> list[tuple[str, str | None, Any]]:
    found: list[tuple[str, str | None, Any]] = []

    def walk(patterns: list[Any], prefix: str, namespace: str | None) -> None:
        for entry in patterns:
            route = prefix + str(entry.pattern)
            if isinstance(entry, URLResolver):
                ns = namespace
                if entry.namespace:
                    ns = f"{namespace}:{entry.namespace}" if namespace else entry.namespace
                walk(entry.url_patterns, route, ns)
            elif isinstance(entry, URLPattern):
                name = f"{namespace}:{entry.name}" if namespace and entry.name else entry.name
                found.append((route, name, entry.callback))

    walk(get_resolver(settings.ROOT_URLCONF).url_patterns, "", None)
    return found


ROUTES = _all_routes()
API_ROUTES = [r for r in ROUTES if not r[0].startswith(ADMIN_PREFIX)]


def _view(callback: Any) -> type[APIView] | None:
    view = getattr(callback, "cls", None) or getattr(callback, "view_class", None)
    return view if isinstance(view, type) and issubclass(view, APIView) else None


def _sample_path(route: str) -> str:
    """A concrete path for a route pattern (random ids, a well-formed but unknown token)."""
    path = re.sub(r"<uuid:[a-z_]+>", lambda _m: str(uuid.uuid4()), route)
    return "/" + re.sub(r"<str:[a-z_]+>", "A" * 43, path)


# ------------------------------------------------------------------------- classification
def test_every_route_is_classified() -> None:
    unclassified = sorted({r for r, _n, _c in API_ROUTES} - set(POLICY))
    assert unclassified == [], f"Classify new routes in POLICY: {unclassified}"
    stale = sorted(set(POLICY) - {r for r, _n, _c in API_ROUTES})
    assert stale == [], f"POLICY lists routes that no longer exist: {stale}"


def test_only_the_admin_is_mounted_outside_the_inventory() -> None:
    others = {r for r, _n, _c in ROUTES if r.startswith(ADMIN_PREFIX)}
    assert others  # the admin exists
    assert all(r.startswith(ADMIN_PREFIX) for r in others)


def test_public_allowlist_matches_the_public_classification_exactly() -> None:
    """The application allowlist (base settings) is exactly the routes classified as public. The
    test settings only add names of test-only fixture routes."""
    from config.settings import base  # noqa: PLC0415

    public_names = {
        name for route, name, _c in API_ROUTES if POLICY[route] in (PUBLIC, TOKEN, DOCS)
    }
    assert public_names == set(base.API_PUBLIC_ENDPOINTS)
    extra = set(settings.API_PUBLIC_ENDPOINTS) - set(base.API_PUBLIC_ENDPOINTS)
    assert all(name.startswith("test-") for name in extra)


@pytest.mark.parametrize(("route", "name", "callback"), API_ROUTES, ids=[r[0] for r in API_ROUTES])
def test_route_matches_its_classification(route: str, name: str | None, callback: Any) -> None:
    kind = POLICY[route]
    view = _view(callback)
    if kind == HEALTH:
        assert view is None  # plain Django probes, never DRF (no data, no authentication)
        return
    assert view is not None, route
    assert issubclass(view, PublicAccessGuard), route  # runtime anonymous-access guard
    permissions = list(view.permission_classes)
    if kind in (PUBLIC, TOKEN, DOCS):
        assert permissions == [PublicEndpoint], route
        assert name in settings.API_PUBLIC_ENDPOINTS
    else:
        assert name not in settings.API_PUBLIC_ENDPOINTS, route
        assert PublicEndpoint not in permissions, route
    if kind == TOKEN:
        assert issubclass(cast(type, view), PublicInvitationView)
        assert "<str:token>" in route
    if kind == AUTHENTICATED:
        assert permissions == [IsAuthenticated], route
        assert not issubclass(view, OrganizationScopedViewMixin), route
        assert "<uuid:org_id>" not in route
    if kind == TENANT:
        assert issubclass(view, OrganizationScopedViewMixin), route
        assert permissions == [HasOrgPermission], route
        assert route.startswith("api/v1/organizations/<uuid:org_id>/")
    if kind == PLATFORM:
        [declared] = permissions
        permission: Any = declared
        assert issubclass(permission, IsPlatformAdministrator), route
        assert route.startswith("api/v1/platform/")
        assert not issubclass(view, OrganizationScopedViewMixin), route
        # Explicit model permissions per method; nothing else is mapped.
        for method in permission.method_permissions:
            assert method in {"GET", "HEAD", "OPTIONS", "POST", "PATCH"}
        assert set(permission.method_permissions.values()) <= {
            "organizations.view_organization",
            "organizations.add_organization",
            "organizations.change_organization",
            "organizations.manage_initial_owner_invitation",
            "audit.view_auditlog",
        }


# ------------------------------------------------------------------------- live checks
@pytest.mark.django_db
@pytest.mark.parametrize(
    "route", [r for r, _n, _c in API_ROUTES if POLICY[r] in (AUTHENTICATED, TENANT, PLATFORM)]
)
def test_anonymous_requests_are_refused_on_every_protected_route(route: str) -> None:
    view = next(_view(c) for r, _n, c in API_ROUTES if r == route)
    for handler in HANDLERS:
        if not hasattr(view, handler):
            continue
        response = getattr(Client(), handler)(
            _sample_path(route), {}, content_type="application/json"
        )
        assert response.status_code == 401, (route, handler, response.status_code)
        assert response["WWW-Authenticate"].startswith("Bearer")


@pytest.mark.django_db
@pytest.mark.parametrize(
    "route", [r for r, _n, _c in API_ROUTES if POLICY[r] in (AUTHENTICATED, TENANT, PLATFORM)]
)
def test_garbage_credentials_are_refused_on_every_protected_route(route: str) -> None:
    for header in ("Bearer x.y.z", "Bearer " + "A" * 500, "Bearer", "Basic dXNlcjpwYXNz"):
        response = Client().get(_sample_path(route), HTTP_AUTHORIZATION=header)
        assert response.status_code == 401, (route, header)


@pytest.mark.django_db
@pytest.mark.parametrize("route", [r for r, _n, _c in API_ROUTES if POLICY[r] == PLATFORM])
def test_platform_routes_require_staff_and_model_permissions(
    route: str, team: Team, as_user: Callable[..., Api], make_user: Callable[..., Any]
) -> None:
    """Tenant Owners, plain staff and non-staff superusers are refused; platform authority is
    never inferred from tenant roles."""
    plain_staff = make_user("plainstaff@example.org", is_staff=True)
    non_staff_superuser = make_user("nsu@example.org", is_superuser=True)
    view = next(_view(c) for r, _n, c in API_ROUTES if r == route)
    for user in (team.owner, team.admin, plain_staff, non_staff_superuser):
        for handler in HANDLERS:
            if hasattr(view, handler):
                response = getattr(as_user(user), handler)(_sample_path(route))
                assert response.status_code == 403, (route, handler, user.email)


@pytest.mark.django_db
@pytest.mark.parametrize("route", [r for r, _n, _c in API_ROUTES if POLICY[r] == DOCS])
def test_documentation_routes_are_disabled_unless_enabled(route: str) -> None:
    """Production forces API_DOCS_ENABLED off (production settings tests); the views check it on
    every request."""
    from django.test import override_settings  # noqa: PLC0415

    with override_settings(API_DOCS_ENABLED=False):
        assert Client().get(_sample_path(route)).status_code == 404


@pytest.mark.django_db
@pytest.mark.parametrize("route", [r for r, _n, _c in API_ROUTES if POLICY[r] == HEALTH])
def test_health_routes_disclose_nothing(route: str) -> None:
    response = Client().get(_sample_path(route))
    assert response.status_code == 200
    # Status words only: no versions, hostnames or exception text.
    assert response.json() in (
        {"status": "ok"},
        {"status": "ok", "checks": {"database": "ok"}},
    )
    assert Client().post(_sample_path(route)).status_code == 405


# ------------------------------------------------------------------------- default deny
class _UndeclaredView:
    action = None
    member_actions = ("get",)
    required_permissions: dict[str, tuple[str, ...]] = {"get": ("organization.view",)}


@pytest.mark.django_db
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"])
def test_undeclared_actions_are_denied_even_for_owners(team: Team, method: str) -> None:
    """Membership-only read access never extends to unsafe methods, and an action with no
    declaration is denied whatever the caller holds."""
    request = type("R", (), {"method": method, "membership": team.membership(team.owner)})()
    assert HasOrgPermission().has_permission(request, _UndeclaredView()) is False


@pytest.mark.django_db
def test_member_actions_apply_to_safe_methods_only(team: Team) -> None:
    view = type("V", (), {"action": None, "member_actions": ("post", "get")})()
    membership = team.membership(team.norole)
    for method, allowed in (("GET", True), ("POST", False)):
        request = type("R", (), {"method": method, "membership": membership})()
        assert HasOrgPermission().has_permission(request, view) is allowed


# ------------------------------------------------------------------------- catalog
@pytest.mark.django_db
def test_registered_codes_and_catalog_rows_agree() -> None:
    rows = dict(CatalogPermission.objects.values_list("code", "is_deprecated"))
    active_rows = {code for code, deprecated in rows.items() if not deprecated}
    registered_active = {code for code in rows if registry.is_active(code)}
    assert active_rows == registered_active
    assert active_rows == {
        "organization.view",
        "organization.update",
        "members.view",
        "members.manage",
        "invitations.manage",
        "roles.view",
        "roles.manage",
        "audit.view",
    }


def test_every_declared_tenant_permission_is_an_active_catalog_code() -> None:
    for route, _name, callback in API_ROUTES:
        view = _view(callback)
        if POLICY[route] != TENANT or view is None:
            continue
        for codes in getattr(view, "required_permissions", {}).values():
            for code in codes:
                assert registry.is_active(code), (route, code)


def test_url_names_are_unique_for_api_views() -> None:
    names = [
        n for n, p in iter_url_patterns(get_resolver().url_patterns) if n and _view(p.callback)
    ]
    assert len(names) == len(set(names))
