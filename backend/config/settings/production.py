"""Hardened production settings.

No deployment is performed in Phase 1; this module exists so the production image can be built
and checked (``manage.py check --deploy``) in CI.
"""

from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F403
from .base import (
    ALLOWED_HOSTS,
    AUTH_PASSWORD_MIN_LENGTH,
    AUTH_REFRESH_COOKIE,
    CORS_ALLOWED_ORIGINS,
    DEBUG,
    JWT_SIGNING_KEY,
    SECRET_KEY,
    env,
)
from .validation import (
    validate_auth_settings,
    validate_cors_origins,
    validate_jwt_signing_key,
    validate_production_settings,
)

# DEBUG comes from the environment (via base) and is validated, not silently overridden:
# DJANGO_DEBUG=true must stop production startup rather than be ignored.
validate_production_settings(secret_key=SECRET_KEY, debug=DEBUG, allowed_hosts=ALLOWED_HOSTS)
validate_cors_origins(CORS_ALLOWED_ORIGINS, require_https=True)
validate_jwt_signing_key(JWT_SIGNING_KEY, secret_key=SECRET_KEY)
validate_auth_settings(
    refresh_cookie_secure=bool(AUTH_REFRESH_COOKIE["SECURE"]),
    password_min_length=AUTH_PASSWORD_MIN_LENGTH,
)

# API documentation stays disabled in production until staff authentication and authorization
# exist. Asking for it is a configuration error rather than something to silently ignore.
if env.bool("DJANGO_API_DOCS_ENABLED", default=False):
    msg = "DJANGO_API_DOCS_ENABLED must be false in production."
    raise ImproperlyConfigured(msg)
API_DOCS_ENABLED = False

# Opt-in only. Enable ONLY when every request reaches Django through a trusted TLS-terminating
# reverse proxy that strips any client-supplied X-Forwarded-Proto header and overwrites it with
# the scheme it actually received. Without such a proxy, clients could spoof the header and make
# plain-HTTP requests appear secure. See README "Production configuration".
if env.bool("DJANGO_BEHIND_TLS_PROXY", default=False):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

SECURE_SSL_REDIRECT = env.bool("DJANGO_SECURE_SSL_REDIRECT", default=True)
# Health probes are served over plain HTTP inside the cluster/container network.
SECURE_REDIRECT_EXEMPT = [r"^health/"]
SECURE_HSTS_SECONDS = env.int("DJANGO_SECURE_HSTS_SECONDS", default=31_536_000)
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = "Strict"
