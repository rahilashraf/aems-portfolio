"""Version 1 of the REST API (mounted at ``/api/v1/``, namespace ``api-v1``).

Tenant routes live under ``organizations/<uuid:org_id>/`` and must use
``OrganizationScopedViewMixin`` (route-coverage meta-test, ADR-0015).
"""

from django.urls import include, path

from apps.core.api.views import ApiRootView

app_name = "api-v1"

urlpatterns = [
    path("", ApiRootView.as_view(), name="root"),
    path("auth/", include("apps.accounts.api.urls", namespace="auth")),
    path("organizations/", include("apps.organizations.api.urls", namespace="organizations")),
    path("platform/", include("apps.organizations.api.platform_urls", namespace="platform")),
]
