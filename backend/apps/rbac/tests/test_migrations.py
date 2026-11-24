"""Upgrade from Batch 5: existing organizations get role definitions, nothing else changes."""

from datetime import timedelta

import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone

from apps.accounts.models import AuthSession, PasswordResetOutbox, User
from apps.audit.models import AuditLog
from apps.organizations.models import Membership, Organization
from apps.rbac.models import MembershipRole, Role

BATCH_5 = [
    ("accounts", "0002_passwordresetoutbox"),
    ("organizations", "0001_initial"),
    ("audit", "0002_append_only_trigger"),
    ("fixtures_app", "0002_tenantnote"),
    ("rbac", None),
]
BATCH_5_NODES = [(app, name) for app, name in BATCH_5 if name is not None]
RBAC_TABLES = {"rbac_permission", "rbac_role", "rbac_membershiprole"}


@pytest.mark.django_db(transaction=True)
def test_upgrade_from_batch_5_seeds_roles_and_preserves_data() -> None:
    executor = MigrationExecutor(connection)
    executor.migrate(BATCH_5)
    assert not RBAC_TABLES & set(connection.introspection.table_names())

    old = executor.loader.project_state(BATCH_5_NODES).apps
    now = timezone.now()
    user = old.get_model("accounts", "User").objects.create(
        email="legacy@example.org", full_name="Legacy", password="!", password_changed_at=now
    )
    old.get_model("accounts", "AuthSession").objects.create(
        user=user, refresh_jti_hash="a" * 64, expires_at=now + timedelta(days=1)
    )
    organization_model = old.get_model("organizations", "Organization")
    statuses = {}
    for slug, status in (("prov", "provisioning"), ("live", "active"), ("paused", "suspended")):
        org = organization_model.objects.create(
            name=slug, slug=slug, organization_type="school", created_by=user, status=status
        )
        statuses[org.pk] = status
        old.get_model("organizations", "Membership").objects.create(
            organization=org, user=user, status="active"
        )
    old.get_model("accounts", "PasswordResetOutbox").objects.create(
        user=user, requested_at=now, expires_at=now, next_attempt_at=now
    )
    old.get_model("audit", "AuditLog").objects.create(action="legacy.event", outcome="success")
    models = (User, AuthSession, Organization, Membership, PasswordResetOutbox, AuditLog)
    before = [list(m.objects.order_by("pk").values()) for m in models]

    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate(executor.loader.graph.leaf_nodes())

    assert set(connection.introspection.table_names()) >= RBAC_TABLES
    assert [list(m.objects.order_by("pk").values()) for m in models] == before
    for organization in Organization.objects.all():
        assert organization.status == statuses[organization.pk]  # no activation
        roles = {r.system_key: r for r in Role.objects.filter(organization=organization)}
        assert set(roles) == {"owner", "admin", "member"}
        assert roles["admin"].permissions.count() == 8
        assert list(roles["member"].permissions.values_list("code", flat=True)) == [
            "organization.view"
        ]
    assert not MembershipRole.objects.exists()  # nobody was made an Owner


@pytest.mark.django_db(transaction=True)
def test_rbac_migrations_are_reversible() -> None:
    executor = MigrationExecutor(connection)
    executor.migrate([("rbac", None)])
    tables = set(connection.introspection.table_names())
    assert not RBAC_TABLES & tables
    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate(executor.loader.graph.leaf_nodes())
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_trigger WHERE tgname = 'rbac_permission_protect'")
        assert cursor.fetchone() == (1,)
        constraints = connection.introspection.get_constraints(cursor, "rbac_membershiprole")
    assert "rbac_mrole_membership_same_org_fk" in constraints
    assert "rbac_mrole_role_same_org_fk" in constraints
