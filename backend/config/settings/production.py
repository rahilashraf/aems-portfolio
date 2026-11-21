"""Hardened production settings.

No deployment is performed in Phase 1; this module exists so the production image can be built
and checked (``manage.py check --deploy``) in CI.
"""

from .base import *  # noqa: F403
from .base import ALLOWED_HOSTS, SECRET_KEY, env
from .validation import validate_production_settings

DEBUG = False

validate_production_settings(secret_key=SECRET_KEY, debug=DEBUG, allowed_hosts=ALLOWED_HOSTS)

# Only honour X-Forwarded-Proto when running behind a trusted TLS-terminating proxy.
if env.bool("DJANGO_BEHIND_TLS_PROXY", default=True):
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
