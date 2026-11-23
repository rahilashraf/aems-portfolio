"""Test URLconf: the real project routes plus test-only routes under ``/test-api/``.

Used via ``@pytest.mark.urls("tests.fixtures_app.urls")``. Error handlers mirror config.urls.
"""

from django.urls import include, path
from rest_framework.routers import SimpleRouter

from config.urls import urlpatterns as project_urlpatterns

from . import tenant_views, views

router = SimpleRouter()
router.register("test-api/actions", views.ActionPermissionsViewSet, basename="test-actions")

# Names listed in config.settings.test API_PUBLIC_ENDPOINTS (test-only public fixtures).
PUBLIC_FIXTURE_NAMES = (
    "test-widgets",
    "test-widgets-all",
    "test-widgets-no-ordering-fields",
    "test-widgets-no-default-ordering",
    "test-auth-failed",
    "test-throttled",
    "test-echo",
    "test-conflict",
    "test-django-404",
    "test-django-403",
    "test-django-validation",
    "test-api-exception",
    "test-unhandled",
    "test-context",
    "test-sensitive-logging",
    "test-actions-list",
    "test-unguarded",
    "test-sensitive-errors",
    "test-sensitive-validation",
)

urlpatterns = [
    *project_urlpatterns,
    path("", include(router.urls)),
    path(
        "test-api/organizations/<uuid:org_id>/notes/",
        tenant_views.TenantNoteListView.as_view(),
        name="test-tenant-notes",
    ),
    path(
        "test-api/organizations/<uuid:org_id>/audit-logs/",
        tenant_views.TestOnlyAuditLogView.as_view(),
        name="test-tenant-audit-logs",
    ),
    path(
        "test-api/organizations/<uuid:org_id>/notes/<str:note_id>/",
        tenant_views.TenantNoteDetailView.as_view(),
        name="test-tenant-note",
    ),
    path("test-api/empty-permissions/", views.EmptyPermissionsView.as_view(), name="test-empty"),
    path("test-api/custom-permissive/", views.CustomPermissiveView.as_view(), name="test-custom"),
    path("test-api/dynamic/", views.DynamicPermissionsView.as_view(), name="test-dynamic"),
    path(
        "test-api/unlisted-public/",
        views.UnlistedPublicEndpointView.as_view(),
        name="test-unlisted-public",
    ),
    path("test-api/unguarded/", views.UnguardedPublicView.as_view(), name="test-unguarded"),
    path(
        "test-api/sensitive-errors/",
        views.SensitiveErrorsView.as_view(),
        name="test-sensitive-errors",
    ),
    path(
        "test-api/sensitive-validation/",
        views.SensitiveValidationView.as_view(),
        name="test-sensitive-validation",
    ),
    path("test-api/widgets/", views.WidgetListView.as_view(), name="test-widgets"),
    path("test-api/widgets-all/", views.WidgetFilterAllView.as_view(), name="test-widgets-all"),
    path(
        "test-api/widgets-no-ordering-fields/",
        views.WidgetNoOrderingFieldsView.as_view(),
        name="test-widgets-no-ordering-fields",
    ),
    path(
        "test-api/widgets-no-default-ordering/",
        views.WidgetNoDefaultOrderingView.as_view(),
        name="test-widgets-no-default-ordering",
    ),
    path("test-api/implicit/", views.ImplicitPermissionView.as_view()),
    path("test-api/auth-required/", views.AuthRequiredView.as_view()),
    path("test-api/auth-failed/", views.AuthFailedView.as_view(), name="test-auth-failed"),
    path("test-api/throttled/", views.ThrottledView.as_view(), name="test-throttled"),
    path("test-api/echo/", views.EchoView.as_view(), name="test-echo"),
    path("test-api/conflict/", views.ConflictView.as_view(), name="test-conflict"),
    path("test-api/django-404/", views.Django404View.as_view(), name="test-django-404"),
    path(
        "test-api/django-403/", views.DjangoPermissionDeniedView.as_view(), name="test-django-403"
    ),
    path(
        "test-api/django-validation/",
        views.DjangoValidationErrorView.as_view(),
        name="test-django-validation",
    ),
    path(
        "test-api/api-exception/",
        views.GenericApiExceptionView.as_view(),
        name="test-api-exception",
    ),
    path("test-api/unhandled/", views.UnhandledErrorView.as_view(), name="test-unhandled"),
    path("test-api/context/", views.ContextView.as_view(), name="test-context"),
    path(
        "test-api/sensitive-logging/",
        views.SensitiveLoggingView.as_view(),
        name="test-sensitive-logging",
    ),
    path("test-django/crash/", views.django_crash),
    path("test-django/suspicious/", views.django_suspicious),
    path("test-django/forbidden/", views.django_forbidden),
    path("test-django/csrf/", views.django_csrf_protected),
]

handler400 = "apps.core.errors.bad_request"
handler403 = "apps.core.errors.permission_denied"
handler404 = "apps.core.errors.page_not_found"
handler500 = "apps.core.errors.server_error"
