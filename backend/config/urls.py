"""Root URL configuration.

- ``/health/``  operational probes (plain Django views; not part of the versioned API)
- ``/api/v1/``  versioned REST API (Django REST Framework)
- ``/api/schema/``, ``/api/docs/``, ``/api/redoc/`` OpenAPI schema and documentation, served only
  when ``API_DOCS_ENABLED`` (local development); always 404 in production.

Django admin is not mounted until the custom user model exists (Batch 3) — see ADR-0002.
"""

from django.urls import include, path

from apps.core.api.views import RedocView, SchemaView, SwaggerView

urlpatterns = [
    path("health/", include("apps.core.urls")),
    path("api/v1/", include("config.api_v1_urls", namespace="api-v1")),
    path("api/schema/", SchemaView.as_view(), name="api-schema"),
    path("api/docs/", SwaggerView.as_view(url_name="api-schema"), name="api-docs"),
    path("api/redoc/", RedocView.as_view(url_name="api-schema"), name="api-redoc"),
]

handler400 = "apps.core.errors.bad_request"
handler403 = "apps.core.errors.permission_denied"
handler404 = "apps.core.errors.page_not_found"
handler500 = "apps.core.errors.server_error"
