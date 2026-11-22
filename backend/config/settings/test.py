"""Settings for the automated test suite.

Defaults let tests run with only ``DATABASE_URL`` set (or none, against a local PostgreSQL).
Tests always run against PostgreSQL.
"""

import os

os.environ.setdefault("DJANGO_SECRET_KEY", "test-only-insecure-secret-key-not-for-production")
os.environ.setdefault("DATABASE_URL", "postgres://aems_app:aems_app@localhost:5432/aems")
os.environ.setdefault(
    "DJANGO_JWT_SIGNING_KEY", "test-only-jwt-signing-key-not-for-production-0123456789abcdef"
)

from apps.core.logging import build_logging_config

from .base import *  # noqa: F403
from .base import API_PUBLIC_ENDPOINTS, INSTALLED_APPS

DEBUG = False
ALLOWED_HOSTS = ["testserver", "localhost"]

# Fast hashing in tests only; production hashing (Argon2id) is covered by dedicated tests that
# override this setting.
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"

# Test-only app providing isolated models/views for exercising shared API infrastructure
# (pagination, filtering, errors). Never installed outside the test settings.
INSTALLED_APPS = [*INSTALLED_APPS, "tests.fixtures_app"]

# Public routes of the test-only fixture URLconf (tests/fixtures_app/urls.py). They exist only
# when a test explicitly selects that URLconf.
API_PUBLIC_ENDPOINTS = (
    *API_PUBLIC_ENDPOINTS,
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

API_DOCS_ENABLED = True
LOG_FORMAT = "json"
LOGGING = build_logging_config(level="WARNING", log_format="json")
