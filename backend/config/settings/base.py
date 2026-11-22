"""Settings shared by every environment.

All environment-specific or secret values are read from environment variables (12-factor).
Environment modules (``local``, ``test``, ``production``) import from here and override.
"""

from pathlib import Path
from typing import Any

import environ

from apps.core.logging import LOG_FORMATS, build_logging_config

from .validation import validate_cors_origins, validate_database_engine, validate_log_format

BASE_DIR = Path(__file__).resolve().parent.parent.parent

env = environ.Env()

# --------------------------------------------------------------------------- core
SECRET_KEY: str = env.str("DJANGO_SECRET_KEY")
DEBUG: bool = env.bool("DJANGO_DEBUG", default=False)
ALLOWED_HOSTS: list[str] = env.list("DJANGO_ALLOWED_HOSTS", default=[])

# Apps with user-related migrations (django.contrib.auth, admin, sessions) are intentionally not
# installed until the custom user model lands in Batch 3, so a default ``auth_user`` table is never
# created. See docs/adr/0002-repository-and-application-architecture.md.
DJANGO_APPS: list[str] = [
    "django.contrib.staticfiles",
]
THIRD_PARTY_APPS: list[str] = [
    "corsheaders",
    "rest_framework",
    "django_filters",
    "drf_spectacular",
]
LOCAL_APPS: list[str] = [
    "apps.core",
]
INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    # First: assigns the request ID and binds log context for everything below it.
    "apps.core.middleware.RequestContextMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

# Templates are only needed by the (development-only) Swagger UI and ReDoc pages.
TEMPLATES: list[dict[str, Any]] = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {"context_processors": ["django.template.context_processors.request"]},
    },
]
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# --------------------------------------------------------------------------- database
# Tests and runtime always use PostgreSQL (never SQLite): later batches rely on JSONB, functional
# unique constraints, row locking, and database triggers.
DATABASES: dict[str, Any] = {
    "default": env.db_url("DATABASE_URL"),
}
validate_database_engine(DATABASES["default"].get("ENGINE", ""))
DATABASES["default"]["ATOMIC_REQUESTS"] = False  # explicit transactions in services (ADR-0006)
DATABASES["default"]["CONN_MAX_AGE"] = env.int("DATABASE_CONN_MAX_AGE", default=60)
DATABASES["default"]["CONN_HEALTH_CHECKS"] = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --------------------------------------------------------------------------- i18n / time
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# --------------------------------------------------------------------------- static files
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

# --------------------------------------------------------------------------- email
# Used by invitations and password reset (Batches 3 and 7). Mailpit in local development.
_email = env.email_url("EMAIL_URL", default="consolemail://")
EMAIL_BACKEND: str = _email["EMAIL_BACKEND"]
EMAIL_HOST: str = _email.get("EMAIL_HOST", "localhost")
EMAIL_PORT: int = int(_email.get("EMAIL_PORT") or 25)
EMAIL_HOST_USER: str = _email.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD: str = _email.get("EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS: bool = bool(_email.get("EMAIL_USE_TLS", False))
EMAIL_USE_SSL: bool = bool(_email.get("EMAIL_USE_SSL", False))
EMAIL_TIMEOUT = 10
DEFAULT_FROM_EMAIL: str = env.str("DEFAULT_FROM_EMAIL", default="AEMS <no-reply@aems.local>")
SERVER_EMAIL = DEFAULT_FROM_EMAIL

# --------------------------------------------------------------------------- security baseline
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
CSRF_COOKIE_HTTPONLY = False  # the SPA must read it for the double-submit pattern (ADR-0004)
CSRF_TRUSTED_ORIGINS: list[str] = env.list("DJANGO_CSRF_TRUSTED_ORIGINS", default=[])
DATA_UPLOAD_MAX_MEMORY_SIZE = 2_621_440  # 2.5 MiB request body cap
# CSRF failures (e.g. on the future cookie-authenticated refresh endpoint) return Problem Details.
CSRF_FAILURE_VIEW = "apps.core.errors.csrf_failure"

# --------------------------------------------------------------------------- CORS
# Secure default: no cross-origin access. Origins must be listed explicitly; credentials are off
# until the cookie-based refresh flow is implemented (Batch 3, ADR-0004).
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS: list[str] = env.list("DJANGO_CORS_ALLOWED_ORIGINS", default=[])
validate_cors_origins(CORS_ALLOWED_ORIGINS, require_https=False)
CORS_ALLOW_CREDENTIALS: bool = env.bool("DJANGO_CORS_ALLOW_CREDENTIALS", default=False)
CORS_URLS_REGEX = r"^/api/.*$"
CORS_EXPOSE_HEADERS = ["X-Request-ID", "Retry-After"]
CORS_PREFLIGHT_MAX_AGE = 600

# --------------------------------------------------------------------------- REST API
REST_FRAMEWORK: dict[str, Any] = {
    # No authentication mechanism exists until Batch 3. An empty list (instead of DRF's session/
    # basic defaults) avoids importing django.contrib.auth, which is intentionally not installed.
    "DEFAULT_AUTHENTICATION_CLASSES": [],
    "UNAUTHENTICATED_USER": None,
    # Deny by default. Public endpoints opt in with PublicEndpoint + API_PUBLIC_ENDPOINTS.
    "DEFAULT_PERMISSION_CLASSES": ["apps.core.api.permissions.DenyAll"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "DEFAULT_PAGINATION_CLASS": "apps.core.api.pagination.StandardPagination",
    "PAGE_SIZE": 25,
    "DEFAULT_FILTER_BACKENDS": [
        "apps.core.api.filtering.AllowlistFilterBackend",
        "apps.core.api.filtering.StableOrderingFilter",
    ],
    "ORDERING_PARAM": "ordering",
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "EXCEPTION_HANDLER": "apps.core.api.exceptions.problem_exception_handler",
    "DEFAULT_THROTTLE_CLASSES": [],
    "TEST_REQUEST_DEFAULT_FORMAT": "json",
    "DATETIME_FORMAT": "iso-8601",
    "COERCE_DECIMAL_TO_STRING": True,
    "STRICT_JSON": True,
}

# URL names of endpoints that may be reached without authentication. Enforced by the
# core.E001/core.E002 system checks (apps/core/checks.py).
API_PUBLIC_ENDPOINTS: tuple[str, ...] = (
    "api-v1:root",
    "api-schema",
    "api-docs",
    "api-redoc",
)

# OpenAPI documentation endpoints. Off unless explicitly enabled; production forces it off.
API_DOCS_ENABLED: bool = env.bool("DJANGO_API_DOCS_ENABLED", default=False)

SPECTACULAR_SETTINGS: dict[str, Any] = {
    "TITLE": "AEMS API",
    "DESCRIPTION": (
        "Assessment & Examination Management System REST API. "
        "Errors use RFC 9457 Problem Details (`application/problem+json`)."
    ),
    "VERSION": "v1",
    "SERVE_INCLUDE_SCHEMA": False,
    "SERVE_PERMISSIONS": ["apps.core.api.permissions.PublicEndpoint"],
    "SERVE_AUTHENTICATION": [],
    "SCHEMA_PATH_PREFIX": r"/api/v1",
    "COMPONENT_SPLIT_REQUEST": True,
    "SORT_OPERATIONS": True,
    "POSTPROCESSING_HOOKS": [
        "drf_spectacular.hooks.postprocess_schema_enums",
        "apps.core.api.openapi.add_problem_responses",
    ],
}

# --------------------------------------------------------------------------- logging
# structlog renders both application and standard-library logs. JSON by default (production);
# local development switches to readable console output.
LOG_LEVEL: str = env.str("DJANGO_LOG_LEVEL", default="INFO")
LOG_FORMAT: str = env.str("DJANGO_LOG_FORMAT", default="json")
validate_log_format(LOG_FORMAT, LOG_FORMATS)
LOGGING: dict[str, Any] = build_logging_config(level=LOG_LEVEL, log_format=LOG_FORMAT)  # type: ignore[arg-type]
