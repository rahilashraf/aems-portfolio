"""Concurrent mutations produce a consistent audit history; upgrading from Batch 4 keeps data."""

import threading
from datetime import timedelta
from itertools import pairwise
from typing import Any

import pytest
from django.db import connection, connections
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone

from apps.accounts.models import AuthSession, PasswordResetOutbox, User
from apps.organizations.models import Membership, Organization
from apps.organizations.services import update_organization

from .conftest import rows


@pytest.mark.django_db(transaction=True)
def test_concurrent_updates_leave_a_consistent_audit_chain(
    make_org: Any, platform_admin: User
) -> None:
    organization = make_org(name="Start")
    workers = 8
    barrier = threading.Barrier(workers)
    errors: list[BaseException] = []

    def rename(index: int) -> None:
        try:
            barrier.wait(timeout=10)
            update_organization(
                actor=platform_admin, organization=organization, changes={"name": f"Name {index}"}
            )
        except BaseException as exc:
            errors.append(exc)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=rename, args=(i,)) for i in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert errors == []
    history = rows(action="organization.updated", organization=organization)
    assert len(history) == workers  # every committed change has exactly one record
    chain = [entry.changes["name"] for entry in history]
    assert chain[0]["from"] == "Start"
    for previous, current in pairwise(chain):
        assert current["from"] == previous["to"]  # serialized by the row lock, no lost updates
    organization.refresh_from_db()
    assert organization.name == chain[-1]["to"]


BATCH_4 = [
    ("accounts", "0002_passwordresetoutbox"),
    ("organizations", "0001_initial"),
    ("fixtures_app", "0002_tenantnote"),
    ("audit", None),
]
BATCH_4_NODES: list[tuple[str, str]] = [(app, name) for app, name in BATCH_4 if name is not None]


@pytest.mark.django_db(transaction=True)
def test_upgrade_from_batch_4_preserves_existing_data() -> None:
    executor = MigrationExecutor(connection)
    executor.migrate(BATCH_4)
    assert "audit_auditlog" not in connection.introspection.table_names()

    old = executor.loader.project_state(BATCH_4_NODES).apps
    now = timezone.now()
    user = old.get_model("accounts", "User").objects.create(
        email="legacy@example.org", full_name="Legacy", password="!", password_changed_at=now
    )
    old.get_model("accounts", "AuthSession").objects.create(
        user=user, refresh_jti_hash="a" * 64, expires_at=now + timedelta(days=1)
    )
    organization = old.get_model("organizations", "Organization").objects.create(
        name="Legacy Org", slug="legacy-org", organization_type="school", created_by=user
    )
    old.get_model("organizations", "Membership").objects.create(
        organization=organization, user=user, status="active"
    )
    old.get_model("accounts", "PasswordResetOutbox").objects.create(
        user=user, requested_at=now, expires_at=now, next_attempt_at=now
    )
    models = (User, AuthSession, Organization, Membership, PasswordResetOutbox)
    before = [list(m.objects.order_by("pk").values()) for m in models]

    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate(executor.loader.graph.leaf_nodes())

    assert "audit_auditlog" in connection.introspection.table_names()
    assert "auth_user" not in connection.introspection.table_names()
    assert [list(m.objects.order_by("pk").values()) for m in models] == before
