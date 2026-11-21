"""Settings shared by every environment.

All environment-specific or secret values are read from environment variables (12-factor).
Environment modules (``local``, ``test``, ``production``) import from here and override.
"""

from pathlib import Path
from typing import Any

import environ

from .validation import validate_database_engine

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
THIRD_PARTY_APPS: list[str] = []
LOCAL_APPS: list[str] = [
    "apps.core",
]
INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
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

# --------------------------------------------------------------------------- logging
# Structured JSON logging (structlog) replaces this in Batch 2.
LOG_LEVEL: str = env.str("DJANGO_LOG_LEVEL", default="INFO")
LOGGING: dict[str, Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "standard"},
    },
    "root": {"handlers": ["console"], "level": LOG_LEVEL},
    "loggers": {
        "django": {"handlers": ["console"], "level": LOG_LEVEL, "propagate": False},
    },
}
