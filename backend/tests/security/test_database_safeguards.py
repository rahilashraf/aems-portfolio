"""Database-level safeguards attacked with raw SQL (plan §7, §11, ADR-0016/0017/0018, ADR-0019).

Most attacks connect as the **runtime role** (the role the application serves requests as) and
bypass the ORM entirely, so only privileges, constraints, composite foreign keys and triggers
stand in the way. ``runtime_dsn`` fails the run when ``AEMS_REQUIRE_RUNTIME_ROLE_TESTS`` is set (CI)
and skips otherwise.
"""

import uuid
from datetime import timedelta
from typing import Any

import psycopg
import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone

from apps.audit import privileges
from apps.audit.models import AuditLog
from apps.organizations.models import Invitation, InvitationRole, Membership
from apps.rbac.models import MembershipRole, Permission
from apps.rbac.tests.conftest import Team, role

pytestmark = pytest.mark.django_db(transaction=True)


def _fails(conn: psycopg.Connection[Any], sql: str, params: Any = None, match: str = "") -> None:
    with pytest.raises(psycopg.Error, match=match or None):
        conn.execute(sql, params)


@pytest.fixture
def runtime(runtime_dsn: str) -> Any:
    with psycopg.connect(runtime_dsn, autocommit=True) as conn:
        yield conn


# ------------------------------------------------------------------------------- the role itself
def test_runtime_role_has_no_elevated_attributes(runtime: psycopg.Connection[Any]) -> None:
    row = runtime.execute(
        "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication "
        "FROM pg_roles WHERE rolname = current_user"
    ).fetchone()
    assert row == (False, False, False, False, False)
    owned = runtime.execute(
        "SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tableowner = current_user"
    ).fetchone()
    assert owned == (0,)


def test_runtime_role_cannot_disable_triggers(runtime: psycopg.Connection[Any]) -> None:
    _fails(runtime, "SET session_replication_role = replica", match="permission denied")
    for table, trigger in (
        ("audit_auditlog", "audit_auditlog_append_only"),
        ("rbac_permission", "rbac_permission_protect"),
        ("organizations_invitation", "organizations_invitation_protect"),
    ):
        _fails(runtime, f"ALTER TABLE {table} DISABLE TRIGGER {trigger}", match="must be owner")
        _fails(runtime, f"DROP TRIGGER {trigger} ON {table}", match="must be owner")


def test_runtime_role_cannot_change_schema_or_privileges(runtime: psycopg.Connection[Any]) -> None:
    for statement in (
        "CREATE TABLE attacker (id int)",
        "ALTER TABLE accounts_user ADD COLUMN backdoor text",
        "DROP TABLE organizations_membership",
        "CREATE ROLE attacker",
    ):
        _fails(runtime, statement)
    # GRANT by a non-owner only warns ("no privileges were granted") and changes nothing.
    runtime.execute("GRANT ALL ON audit_auditlog TO PUBLIC")
    grants = runtime.execute(
        "SELECT privilege_type FROM information_schema.role_table_grants "
        "WHERE table_name = 'audit_auditlog' AND grantee IN ('PUBLIC', current_user) "
        "ORDER BY 1"
    ).fetchall()
    assert grants == [("INSERT",), ("SELECT",)]


# ------------------------------------------------------------------------------- audit
def test_audit_rows_are_read_and_append_only(runtime: psycopg.Connection[Any]) -> None:
    entry = AuditLog.objects.create(action="test.committed", outcome="success")
    for statement in (
        "UPDATE audit_auditlog SET action = 'tampered.event'",
        "UPDATE audit_auditlog SET metadata = '{}'::jsonb WHERE id = %s",
        "DELETE FROM audit_auditlog",
        "DELETE FROM audit_auditlog WHERE id = %s",
        "TRUNCATE audit_auditlog",
    ):
        params = [entry.pk] if "%s" in statement else None
        _fails(runtime, statement, params, match="permission denied")
    assert AuditLog.objects.get(pk=entry.pk).action == "test.committed"


def test_even_the_owner_role_cannot_update_or_delete_audit_rows() -> None:
    entry = AuditLog.objects.create(action="test.committed", outcome="success")
    from django.db import DatabaseError, transaction  # noqa: PLC0415

    for statement in (
        "UPDATE audit_auditlog SET action = 'x.y' WHERE id = %s",
        "DELETE FROM audit_auditlog WHERE id = %s",
    ):
        with pytest.raises(DatabaseError), transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(statement, [entry.pk])
    assert AuditLog.objects.filter(pk=entry.pk, action="test.committed").exists()


# ------------------------------------------------------------------------------- RBAC catalog
def test_permission_catalog_is_protected(runtime: psycopg.Connection[Any]) -> None:
    code = "members.manage"
    _fails(runtime, "UPDATE rbac_permission SET code = 'members.own' WHERE code = %s", [code])
    _fails(runtime, "DELETE FROM rbac_permission WHERE code = %s", [code])
    assert Permission.objects.filter(code=code).exists()


# ------------------------------------------------------------------------------- tenancy
def test_cross_tenant_role_assignment_is_impossible_in_sql(
    team: Team, runtime: psycopg.Connection[Any]
) -> None:
    membership = team.membership(team.member)
    foreign_owner = role(team.other, "owner")
    for organization_id in (team.org.pk, team.other.pk):
        _fails(
            runtime,
            "INSERT INTO rbac_membershiprole (id, organization_id, membership_id, role_id, "
            "assigned_at, created_at, updated_at) VALUES (%s, %s, %s, %s, now(), now(), now())",
            [uuid.uuid4(), organization_id, membership.pk, foreign_owner.pk],
            match="foreign key",
        )
    assert not MembershipRole.objects.filter(membership=membership, role=foreign_owner).exists()


def test_rows_referenced_across_tables_cannot_change_tenant(
    team: Team, runtime: psycopg.Connection[Any]
) -> None:
    membership = team.membership(team.admin)  # holds Admin in A
    _fails(
        runtime,
        "UPDATE organizations_membership SET organization_id = %s WHERE id = %s",
        [team.other.pk, membership.pk],
        match="foreign key|unique",
    )
    _fails(
        runtime,
        "UPDATE rbac_role SET organization_id = %s WHERE id = %s",
        [team.other.pk, team.auditors.pk],
        match="foreign key|unique",
    )
    _fails(
        runtime,
        "UPDATE rbac_membershiprole SET organization_id = %s WHERE membership_id = %s",
        [team.other.pk, membership.pk],
        match="foreign key",
    )
    assert Membership.objects.get(pk=membership.pk).organization_id == team.org.pk


# ------------------------------------------------------------------------------- invitations
def _pending(team: Team, email: str = "sql@example.org") -> Invitation:
    invitation = Invitation(
        organization=team.org,
        email=email,
        invited_by=team.owner,
        expires_at=timezone.now() + timedelta(days=7),
    )
    invitation.save()
    InvitationRole(
        organization=team.org, invitation=invitation, role=role(team.org, "member")
    ).save()
    return invitation


def test_invitation_safeguards(team: Team, runtime: psycopg.Connection[Any]) -> None:
    invitation = _pending(team)
    # Identity columns of a pending invitation are immutable.
    for column, value in (
        ("organization_id", team.other.pk),
        ("email", "attacker@evil.test"),
        ("is_initial_owner", True),
        ("invited_by_id", team.outsider.pk),
    ):
        _fails(
            runtime,
            f"UPDATE organizations_invitation SET {column} = %s WHERE id = %s",  # noqa: S608
            [value, invitation.pk],
        )
    # Deletes are refused.
    _fails(runtime, "DELETE FROM organizations_invitation WHERE id = %s", [invitation.pk])
    # A second pending invitation for the address is refused.
    _fails(
        runtime,
        "INSERT INTO organizations_invitation (id, organization_id, email, is_initial_owner, "
        "status, token_hash, invited_by_id, expires_at, created_at, updated_at) VALUES "
        "(%s, %s, %s, false, 'pending', NULL, %s, now() + interval '1 day', now(), now())",
        [uuid.uuid4(), team.org.pk, invitation.email, team.owner.pk],
        match="unique|duplicate",
    )
    # A cross-tenant role link is refused.
    _fails(
        runtime,
        "INSERT INTO organizations_invitationrole (id, organization_id, invitation_id, role_id, "
        "created_at, updated_at) VALUES (%s, %s, %s, %s, now(), now())",
        [uuid.uuid4(), team.org.pk, invitation.pk, role(team.other, "owner").pk],
        match="foreign key",
    )
    # Terminal states are final: a revoked invitation cannot be revived or accepted.
    runtime.execute(
        "UPDATE organizations_invitation SET status = 'revoked', revoked_at = now(), "
        "revoked_by_id = %s WHERE id = %s",
        [team.owner.pk, invitation.pk],
    )
    _fails(
        runtime,
        "UPDATE organizations_invitation SET status = 'pending', revoked_at = NULL, "
        "revoked_by_id = NULL WHERE id = %s",
        [invitation.pk],
    )
    assert Invitation.objects.get(pk=invitation.pk).status == "revoked"


def test_token_digest_format_is_enforced(team: Team, runtime: psycopg.Connection[Any]) -> None:
    invitation = _pending(team, "digest@example.org")
    for value in ("plaintext-token", "A" * 64, "0" * 63):
        _fails(
            runtime,
            "UPDATE organizations_invitation SET token_hash = %s WHERE id = %s",
            [value, invitation.pk],
            match="check constraint|organizations_invitation_token_hash_format",
        )


# ------------------------------------------------------------------------------- migrations
def test_local_migrations_reverse_and_reapply_cleanly() -> None:
    """Roll the Batch 4-7 schema (organizations, rbac, audit and the fixture app) back to zero and
    forward again: every migration is reversible, and the triggers and grants come back."""
    executor = MigrationExecutor(connection)
    executor.migrate(
        [("audit", None), ("rbac", None), ("fixtures_app", None), ("organizations", None)]
    )
    tables = set(connection.introspection.table_names())
    assert not {"audit_auditlog", "rbac_role", "organizations_invitation"} & tables
    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate(executor.loader.graph.leaf_nodes())
    privileges.grant_runtime_privileges()
    from apps.rbac.registry import sync_permissions  # noqa: PLC0415

    sync_permissions()
    with connection.cursor() as cursor:
        cursor.execute("SELECT tgname FROM pg_trigger WHERE NOT tgisinternal ORDER BY tgname")
        triggers = [row[0] for row in cursor.fetchall()]
    assert triggers == [
        "audit_auditlog_append_only",
        "organizations_invitation_protect",
        "rbac_permission_protect",
    ]
    assert not MigrationExecutor(connection).migration_plan(
        MigrationExecutor(connection).loader.graph.leaf_nodes()
    )
