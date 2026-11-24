"""Audit test fixtures: reuse the organization world and accounts helpers."""

import os
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import pytest
from django.db import connection

from apps.accounts.tests.conftest import events, login, user  # noqa: F401 - fixtures
from apps.audit.models import AuditLog
from apps.organizations.tests.conftest import (  # noqa: F401 - fixtures
    api,
    make_org,
    make_user,
    platform_admin,
    world,
)

RUNTIME_URL_ENV = "AEMS_RUNTIME_DATABASE_URL"


def rows(**filters: Any) -> list[AuditLog]:
    return list(AuditLog.objects.filter(**filters).order_by("created_at", "id"))


def all_rows_text() -> str:
    return repr(list(AuditLog.objects.values()))


@pytest.fixture
def runtime_dsn() -> str:
    """Connection string for the runtime role, pointed at the current test database."""
    raw = os.environ.get(RUNTIME_URL_ENV, "")
    if not raw:
        if os.environ.get("AEMS_REQUIRE_RUNTIME_ROLE_TESTS"):
            pytest.fail(f"{RUNTIME_URL_ENV} is required for the database-privilege tests.")
        pytest.skip(f"{RUNTIME_URL_ENV} not set (run via `make test`).")
    parts = urlsplit(raw)
    return urlunsplit(parts._replace(path="/" + connection.settings_dict["NAME"]))
