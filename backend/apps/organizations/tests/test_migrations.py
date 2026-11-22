"""Upgrade path: a Batch 3 database with users and sessions gains the organizations schema."""

from datetime import timedelta

import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone

from apps.accounts.models import AuthSession, User

BATCH_3_STATE = [("fixtures_app", "0001_initial"), ("organizations", None)]
BATCH_3_NODES = [("accounts", "0002_passwordresetoutbox"), ("fixtures_app", "0001_initial")]
NEW_TABLES = {"organizations_organization", "organizations_membership"}


@pytest.mark.django_db(transaction=True)
def test_upgrade_from_batch_3_preserves_users_and_sessions() -> None:
    executor = MigrationExecutor(connection)
    executor.migrate(BATCH_3_STATE)
    assert not NEW_TABLES & set(connection.introspection.table_names())

    old_apps = executor.loader.project_state(BATCH_3_NODES).apps
    old_user = old_apps.get_model("accounts", "User")
    old_session = old_apps.get_model("accounts", "AuthSession")
    now = timezone.now()
    user = old_user.objects.create(
        email="legacy@example.org", full_name="Legacy", password="!", password_changed_at=now
    )
    old_session.objects.create(
        user=user, refresh_jti_hash="a" * 64, expires_at=now + timedelta(days=1)
    )
    snapshot = (list(old_user.objects.order_by("id").values()), list(old_session.objects.values()))

    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate(executor.loader.graph.leaf_nodes())

    assert set(connection.introspection.table_names()) >= NEW_TABLES
    assert "auth_user" not in connection.introspection.table_names()
    assert (
        list(User.objects.order_by("id").values()),
        list(AuthSession.objects.values()),
    ) == snapshot


@pytest.mark.django_db
def test_schema_constraints_and_indexes_exist() -> None:
    with connection.cursor() as cursor:
        constraints = connection.introspection.get_constraints(cursor, "organizations_membership")
        org_constraints = connection.introspection.get_constraints(
            cursor, "organizations_organization"
        )
    unique = constraints["organizations_membership_org_user_uniq"]
    assert unique["unique"]
    assert unique["columns"] == ["organization_id", "user_id"]
    assert constraints["orgs_membership_user_status"]["columns"] == ["user_id", "status"]
    foreign_keys = {
        tuple(c["columns"]): c["foreign_key"] for c in constraints.values() if c["foreign_key"]
    }
    assert foreign_keys[("organization_id",)][0] == "organizations_organization"
    assert foreign_keys[("user_id",)][0] == "accounts_user"
    assert org_constraints["organizations_org_slug_uniq"]["unique"]
    for name in (
        "organizations_org_slug_format",
        "organizations_org_name_not_blank",
        "organizations_org_type_valid",
        "organizations_org_status_valid",
    ):
        assert org_constraints[name]["check"], name
