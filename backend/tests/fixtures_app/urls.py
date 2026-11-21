"""Test URLconf: the real project routes plus test-only routes under ``/test-api/``.

Used via ``@pytest.mark.urls("tests.fixtures_app.urls")``. Error handlers mirror config.urls.
"""

from django.urls import path

from config.urls import urlpatterns as project_urlpatterns

from . import views

urlpatterns = [
    *project_urlpatterns,
    path("test-api/widgets/", views.WidgetListView.as_view(), name="widgets"),
    path("test-api/widgets-all/", views.WidgetFilterAllView.as_view()),
    path("test-api/widgets-no-ordering-fields/", views.WidgetNoOrderingFieldsView.as_view()),
    path("test-api/widgets-no-default-ordering/", views.WidgetNoDefaultOrderingView.as_view()),
    path("test-api/implicit/", views.ImplicitPermissionView.as_view()),
    path("test-api/auth-required/", views.AuthRequiredView.as_view()),
    path("test-api/auth-failed/", views.AuthFailedView.as_view()),
    path("test-api/throttled/", views.ThrottledView.as_view()),
    path("test-api/echo/", views.EchoView.as_view()),
    path("test-api/conflict/", views.ConflictView.as_view()),
    path("test-api/django-404/", views.Django404View.as_view()),
    path("test-api/django-403/", views.DjangoPermissionDeniedView.as_view()),
    path("test-api/django-validation/", views.DjangoValidationErrorView.as_view()),
    path("test-api/api-exception/", views.GenericApiExceptionView.as_view()),
    path("test-api/unhandled/", views.UnhandledErrorView.as_view()),
    path("test-api/context/", views.ContextView.as_view()),
    path("test-api/sensitive-logging/", views.SensitiveLoggingView.as_view()),
    path("test-django/crash/", views.django_crash),
    path("test-django/suspicious/", views.django_suspicious),
    path("test-django/forbidden/", views.django_forbidden),
    path("test-django/csrf/", views.django_csrf_protected),
]

handler400 = "apps.core.errors.bad_request"
handler403 = "apps.core.errors.permission_denied"
handler404 = "apps.core.errors.page_not_found"
handler500 = "apps.core.errors.server_error"
