"""Version 1 of the REST API (mounted at ``/api/v1/``, namespace ``api-v1``).

Domain apps add their routes here in later batches, e.g.
``path("organizations/", include("apps.organizations.api.urls"))``.
"""

from django.urls import include, path

from apps.core.api.views import ApiRootView

app_name = "api-v1"

urlpatterns = [
    path("", ApiRootView.as_view(), name="root"),
    path("auth/", include("apps.accounts.api.urls", namespace="auth")),
]
