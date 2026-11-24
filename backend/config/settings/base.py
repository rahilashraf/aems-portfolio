"""Settings shared by every environment.

All environment-specific or secret values are read from environment variables (12-factor).
Environment modules (``local``, ``test``, ``production``) import from here and override.
"""

from datetime import timedelta
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

# django.contrib.auth is installed together with the custom user model (AUTH_USER_MODEL below), so
# the default ``auth_user`` table is never created (ADR-0002). auth still provides Group/Permission
# tables used by PermissionsMixin and the platform admin.
DJANGO_APPS: list[str] = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
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
    "apps.accounts",
    "apps.organizations",
    "apps.rbac",
    "apps.audit",
]
INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    # First: assigns the request ID and binds log context for everything below it.
    "apps.core.middleware.RequestContextMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    # Sessions/auth/messages serve the staff-only Django admin; the API uses bearer tokens.
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

# Templates serve the staff-only admin and the (development-only) Swagger UI / ReDoc pages.
TEMPLATES: list[dict[str, Any]] = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    },
]

# Platform administration (staff only). Path configurable to reduce automated probing.
ADMIN_URL: str = env.str("DJANGO_ADMIN_URL", default="admin/")
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
# The runtime role the application connects as in production (ADR-0016). Migrations run as the
# owner role; after every migrate this role is granted its privileges (audit table: SELECT and
# INSERT only). Unset: no grants are issued (single-role setups have no audit privilege boundary).
DATABASE_RUNTIME_ROLE: str | None = env.str("DJANGO_DB_RUNTIME_ROLE", default="") or None

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
    # Bearer access tokens validated against the server-side session on every request (ADR-0004).
    "DEFAULT_AUTHENTICATION_CLASSES": ["apps.accounts.authentication.SessionJWTAuthentication"],
    # Authenticated by default (ADR-0012). Public endpoints opt in with PublicEndpoint +
    # API_PUBLIC_ENDPOINTS; DenyAll remains available for explicit lockdown.
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
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
    # Authentication (Batch 3). Logout is public so an expired access token cannot prevent it.
    "api-v1:auth:csrf",
    "api-v1:auth:login",
    "api-v1:auth:token-refresh",
    "api-v1:auth:logout",
    "api-v1:auth:password-reset",
    "api-v1:auth:password-reset-confirm",
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
    # Several models have a "status" field; name each enum explicitly.
    "ENUM_NAME_OVERRIDES": {
        "OrganizationStatusEnum": "apps.organizations.models.OrganizationStatus",
        "MembershipStatusEnum": "apps.organizations.models.MembershipStatus",
        "OrganizationTypeEnum": "apps.organizations.models.OrganizationType",
    },
}

# --------------------------------------------------------------------------- identity & auth
AUTH_USER_MODEL = "accounts.User"
AUTHENTICATION_BACKENDS = ["apps.accounts.backends.EmailBackend"]
# Email uniqueness is enforced case-insensitively by UniqueConstraint(Lower("email")) (ADR-0008),
# which Django's auth.W004 check (expects unique=True on USERNAME_FIELD) cannot see.
SILENCED_SYSTEM_CHECKS = ["auth.W004"]

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",  # Argon2id (preferred)
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",  # verification/upgrade only
]
AUTH_PASSWORD_MIN_LENGTH: int = env.int("DJANGO_PASSWORD_MIN_LENGTH", default=12)
AUTH_PASSWORD_VALIDATORS: list[dict[str, Any]] = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": AUTH_PASSWORD_MIN_LENGTH},
    },
    {"NAME": "apps.accounts.validators.MaximumLengthValidator", "OPTIONS": {"max_length": 128}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Password reset: single-use tokens bound to the password, its change time and last login.
PASSWORD_RESET_TIMEOUT: int = env.int("DJANGO_PASSWORD_RESET_TIMEOUT", default=3600)
FRONTEND_BASE_URL: str = env.str("AEMS_FRONTEND_BASE_URL", default="http://localhost:3000")
# The token travels in the URL fragment (never sent to servers or in Referer headers).
PASSWORD_RESET_URL_TEMPLATE: str = (
    FRONTEND_BASE_URL.rstrip("/") + "/reset-password#uid={uid}&token={token}"
)
# Password-reset email outbox (ADR-0014). Requests only enqueue; the
# `deliver_password_reset_emails` command sends, and must be run regularly (e.g. every minute).
PASSWORD_RESET_OUTBOX: dict[str, int] = {
    # A request not delivered within this time is discarded (the user can ask again).
    "ttl_seconds": env.int("AEMS_PASSWORD_RESET_EMAIL_TTL_SECONDS", default=900),
    "max_attempts": env.int("AEMS_PASSWORD_RESET_EMAIL_MAX_ATTEMPTS", default=5),
    # Retry delay: base * 2^(attempt - 1), capped.
    "backoff_base_seconds": 60,
    "backoff_cap_seconds": 900,
    # A claim expires after this, so work held by a crashed command is retried. Must exceed
    # EMAIL_TIMEOUT, because one claim covers one SMTP exchange.
    "lease_seconds": 120,
    # Finished rows (delivered, failed, expired, cancelled) are deleted after this.
    "retention_seconds": 7 * 24 * 3600,
    "max_batch_size": 1000,
}

# JWT (SimpleJWT primitives) signed with a dedicated key, never SECRET_KEY.
JWT_SIGNING_KEY: str = env.str("DJANGO_JWT_SIGNING_KEY")
_JWT_KIND_CLAIM = "type"  # claim that distinguishes access from refresh tokens
SIMPLE_JWT: dict[str, Any] = {
    "ALGORITHM": "HS256",
    "SIGNING_KEY": JWT_SIGNING_KEY,
    "VERIFYING_KEY": "",
    "AUDIENCE": env.str("DJANGO_JWT_AUDIENCE", default="") or None,
    "ISSUER": env.str("DJANGO_JWT_ISSUER", default="") or None,
    "LEEWAY": 0,
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=10),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "sub",
    "TOKEN_TYPE_CLAIM": _JWT_KIND_CLAIM,
    "JTI_CLAIM": "jti",
    "AUTH_HEADER_TYPES": ("Bearer",),
    "UPDATE_LAST_LOGIN": False,
    "ROTATE_REFRESH_TOKENS": False,  # rotation is implemented by AuthSession (accounts.sessions)
    "BLACKLIST_AFTER_ROTATION": False,
}
AUTH_SESSION_ABSOLUTE_LIFETIME_SECONDS: int = 30 * 24 * 3600

AUTH_REFRESH_COOKIE: dict[str, Any] = {
    "NAME": "aems_refresh",
    "PATH": "/api/v1/auth/",
    "SECURE": env.bool("DJANGO_AUTH_REFRESH_COOKIE_SECURE", default=True),
    "SAMESITE": "Strict",
    "DOMAIN": None,
}
CSRF_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_AGE = 8 * 3600  # admin sessions

# Atomic PostgreSQL-backed limits: scope -> (max attempts, window seconds).
AUTH_RATE_LIMITS: dict[str, tuple[int, int]] = {
    "login_ip": (30, 300),
    "login_account": (10, 900),
    "login_ip_account": (5, 900),
    "refresh_ip": (120, 300),
    "password_reset_ip": (10, 3600),
    "password_reset_account": (3, 3600),
    "password_reset_confirm_ip": (20, 3600),
    "password_change_user": (10, 3600),
}
# Temporary exponential account backoff after consecutive failures (capped).
AUTH_LOGIN_BACKOFF: dict[str, int] = {"threshold": 5, "base_seconds": 30, "cap_seconds": 900}

# Client IP: REMOTE_ADDR unless the exact number of trusted reverse proxies is configured.
TRUSTED_PROXY_COUNT: int = env.int("DJANGO_TRUSTED_PROXY_COUNT", default=0)

# --------------------------------------------------------------------------- logging
# structlog renders both application and standard-library logs. JSON by default (production);
# local development switches to readable console output.
LOG_LEVEL: str = env.str("DJANGO_LOG_LEVEL", default="INFO")
LOG_FORMAT: str = env.str("DJANGO_LOG_FORMAT", default="json")
validate_log_format(LOG_FORMAT, LOG_FORMATS)
LOGGING: dict[str, Any] = build_logging_config(level=LOG_LEVEL, log_format=LOG_FORMAT)  # type: ignore[arg-type]
