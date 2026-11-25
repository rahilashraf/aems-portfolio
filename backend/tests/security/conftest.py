"""Fixtures for the cross-cutting security suites (plan §10, ADR-0019).

The suites reuse the per-app fixtures (users, organizations, the RBAC ``team``) so every attack
runs against the same data the application tests use.
"""

from apps.accounts.tests.conftest import events, login  # noqa: F401 - re-exported fixtures
from apps.audit.tests.conftest import runtime_dsn  # noqa: F401 - re-exported fixture
from apps.organizations.tests.conftest import (  # noqa: F401 - re-exported fixtures
    api,
    as_user,
    make_org,
    make_user,
    platform_admin,
    team,
    world,
)
