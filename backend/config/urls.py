"""Root URL configuration.

The versioned API (``/api/v1/``) is introduced in Batch 2. Django admin is deliberately not
mounted until the custom user model exists (Batch 3) — see ADR-0002.
"""

from django.urls import include, path

urlpatterns = [
    path("health/", include("apps.core.urls")),
]
