"""Local development settings (Docker Compose or a host virtualenv). Never use in production."""

from apps.core.logging import build_logging_config

from .base import *  # noqa: F403
from .base import LOG_LEVEL, env
from .validation import validate_cors_origins

DEBUG = env.bool("DJANGO_DEBUG", default=True)
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"])
LOG_FORMAT = env.str("DJANGO_LOG_FORMAT", default="console")
LOGGING = build_logging_config(level=LOG_LEVEL, log_format=LOG_FORMAT)  # type: ignore[arg-type]
API_DOCS_ENABLED = env.bool("DJANGO_API_DOCS_ENABLED", default=True)
CORS_ALLOWED_ORIGINS = env.list("DJANGO_CORS_ALLOWED_ORIGINS", default=["http://localhost:3000"])
validate_cors_origins(CORS_ALLOWED_ORIGINS, require_https=False)
