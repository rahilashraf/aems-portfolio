"""Fail-fast validation of security-critical configuration.

Kept separate from the settings modules so the rules are unit-testable without re-importing
settings.
"""

from collections.abc import Sequence
from urllib.parse import urlsplit

from django.core.exceptions import ImproperlyConfigured

SUPPORTED_DATABASE_ENGINE = "django.db.backends.postgresql"
MIN_SECRET_KEY_LENGTH = 50
MIN_SECRET_KEY_UNIQUE_CHARS = 5
_INSECURE_MARKERS = ("insecure", "change-me", "changeme", "dev-only", "test-only", "example")


def validate_secret_key(secret_key: str) -> None:
    """Reject missing, short, low-entropy, or obviously placeholder secret keys."""
    if len(secret_key) < MIN_SECRET_KEY_LENGTH:
        msg = f"DJANGO_SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters."
        raise ImproperlyConfigured(msg)
    if len(set(secret_key)) < MIN_SECRET_KEY_UNIQUE_CHARS:
        msg = "DJANGO_SECRET_KEY has too little variety to be a random secret."
        raise ImproperlyConfigured(msg)
    lowered = secret_key.lower()
    if lowered.startswith("django-insecure") or any(m in lowered for m in _INSECURE_MARKERS):
        msg = "DJANGO_SECRET_KEY looks like a placeholder; generate a random production secret."
        raise ImproperlyConfigured(msg)


def validate_log_format(log_format: str, supported: Sequence[str]) -> None:
    if log_format not in supported:
        msg = f"DJANGO_LOG_FORMAT must be one of {', '.join(supported)}; got {log_format!r}."
        raise ImproperlyConfigured(msg)


def validate_cors_origins(origins: Sequence[str], *, require_https: bool) -> None:
    """Reject wildcard, ``null`` and malformed CORS origins (and plain HTTP when required)."""
    for origin in origins:
        parts = urlsplit(origin)
        if origin in ("*", "null") or parts.scheme not in ("http", "https") or not parts.netloc:
            msg = f"Invalid CORS origin {origin!r}: use an explicit scheme://host[:port] origin."
            raise ImproperlyConfigured(msg)
        if parts.path not in ("", "/") or parts.query or parts.fragment:
            msg = f"Invalid CORS origin {origin!r}: an origin has no path, query or fragment."
            raise ImproperlyConfigured(msg)
        if require_https and parts.scheme != "https":
            msg = f"CORS origin {origin!r} must use https in production."
            raise ImproperlyConfigured(msg)


def validate_production_settings(
    *, secret_key: str, debug: bool, allowed_hosts: Sequence[str]
) -> None:
    """Raise ``ImproperlyConfigured`` if production settings are unsafe."""
    if debug:
        msg = "DJANGO_DEBUG must be false in production."
        raise ImproperlyConfigured(msg)
    validate_secret_key(secret_key)
    if not allowed_hosts:
        msg = "DJANGO_ALLOWED_HOSTS must be set in production."
        raise ImproperlyConfigured(msg)
    if "*" in allowed_hosts:
        msg = "DJANGO_ALLOWED_HOSTS must not contain '*' in production."
        raise ImproperlyConfigured(msg)


def validate_database_engine(engine: str) -> None:
    """Reject any database backend other than PostgreSQL, in every environment.

    AEMS relies on PostgreSQL-specific behaviour (functional unique constraints, row locking,
    JSONB, triggers, and future row-level security). Running on SQLite or another engine would
    silently weaken those guarantees, so startup fails instead.
    """
    if engine != SUPPORTED_DATABASE_ENGINE:
        msg = (
            f"Unsupported database engine {engine!r}: DATABASE_URL must point to PostgreSQL "
            f"({SUPPORTED_DATABASE_ENGINE})."
        )
        raise ImproperlyConfigured(msg)
