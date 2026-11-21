"""Settings for the automated test suite.

Defaults let tests run with only ``DATABASE_URL`` set (or none, against a local PostgreSQL).
Tests always run against PostgreSQL.
"""

import os

os.environ.setdefault("DJANGO_SECRET_KEY", "test-only-insecure-secret-key-not-for-production")
os.environ.setdefault("DATABASE_URL", "postgres://aems_app:aems_app@localhost:5432/aems")

from .base import *  # noqa: F403
from .base import LOGGING

DEBUG = False
ALLOWED_HOSTS = ["testserver", "localhost"]

# Fast, deterministic hashing in tests only. Production hashing (Argon2id) arrives in Batch 3.
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"

LOGGING["root"]["level"] = "WARNING"
LOGGING["loggers"]["django"]["level"] = "WARNING"
