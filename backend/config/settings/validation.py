"""Fail-fast validation of security-critical production configuration.

Kept separate from ``production.py`` so the rules are unit-testable without re-importing settings.
"""

from collections.abc import Sequence

from django.core.exceptions import ImproperlyConfigured

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
