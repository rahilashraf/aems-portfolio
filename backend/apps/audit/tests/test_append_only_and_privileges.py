"""Append-only audit records: ORM guards, the PostgreSQL trigger and runtime-role privileges."""

import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import psycopg
import pytest
from django.contrib import admin
from django.core.exceptions import ImproperlyConfigured
from django.db import DatabaseError, IntegrityError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import override_settings

from apps.audit import privileges
from apps.audit.admin import AuditLogAdmin
from apps.audit.models import AuditLog, AuditLogImmutableError, MissingAuditScopeError
from apps.audit.services import record_security_event

BACKEND_DIR = Path(__file__).resolve().parents[3]
INSERT_SQL = (
    "INSERT INTO audit_auditlog (id, action, outcome, actor_email, target_type, target_id, "
    "changes, metadata, user_agent, request_id, created_at) "
    "VALUES (%s, %s, %s, '', '', '', '{}', '{}', '', '', now())"
)


def _entry(action: str = "test.recorded") -> AuditLog:
    return record_security_event(action, outcome="success")


# ------------------------------------------------------------------------------ ORM layer
@pytest.mark.django_db
class TestOrmGuards:
    def test_existing_rows_cannot_be_saved_or_deleted(self) -> None:
        entry = _entry()
        entry.action = "tampered.event"
        for attempt in (
            entry.save,
            lambda: entry.save(update_fields=["action"]),
            entry.delete,
            lambda: AuditLog(id=entry.id, action="x.y", outcome="success").save(force_update=True),
        ):
            with pytest.raises(AuditLogImmutableError):
                attempt()
        assert AuditLog.objects.get(pk=entry.pk).action == "test.recorded"

    def test_queryset_mutations_are_refused(self) -> None:
        entry = _entry()
        queryset = AuditLog.objects.filter(pk=entry.pk)
        for attempt in (
            lambda: queryset.update(action="tampered.event"),
            queryset.delete,
            lambda: AuditLog.objects.bulk_update([entry], ["action"]),
            lambda: AuditLog.objects.bulk_create([AuditLog(action="x.y", outcome="success")]),
            lambda: AuditLog.objects.bulk_create(
                [AuditLog(id=entry.id, action="tampered.event", outcome="success")],
                update_conflicts=True,
                unique_fields=["id"],
                update_fields=["action"],
            ),
        ):
            with pytest.raises(AuditLogImmutableError):
                attempt()
        assert AuditLog.objects.get(pk=entry.pk).action == "test.recorded"

    def test_tenant_reads_fail_closed(self, make_org: Any) -> None:
        organization = make_org()
        with pytest.raises(MissingAuditScopeError):
            AuditLog.objects.for_organization(None)
        with pytest.raises(MissingAuditScopeError):
            AuditLog.objects.for_organization(type(organization)())
        assert list(AuditLog.objects.for_organization(organization)) == list(
            AuditLog.objects.filter(organization=organization)
        )

    def test_platform_events_exclude_organization_rows(self, make_org: Any) -> None:
        org_entry = AuditLog.objects.filter(organization=make_org()).first()
        assert org_entry is None or org_entry not in AuditLog.objects.platform_events()
        assert _entry() in AuditLog.objects.platform_events()

    def test_admin_is_read_only(self, rf: Any) -> None:
        model_admin = admin.site._registry[AuditLog]
        assert isinstance(model_admin, AuditLogAdmin)
        request = rf.get("/")
        entry = _entry()
        assert not model_admin.has_add_permission(request)
        assert not model_admin.has_change_permission(request, entry)
        assert not model_admin.has_delete_permission(request, entry)
        assert model_admin.actions is None
        assert set(model_admin.get_readonly_fields(request, entry)) >= {"action", "metadata"}


# ------------------------------------------------------------------------ database layer
@pytest.mark.django_db
class TestDatabaseTrigger:
    def test_raw_update_and_delete_are_rejected(self) -> None:
        entry = _entry()
        for statement in (
            "UPDATE audit_auditlog SET action = 'tampered.event' WHERE id = %s",
            "DELETE FROM audit_auditlog WHERE id = %s",
        ):
            with (
                pytest.raises(DatabaseError, match="append-only"),
                transaction.atomic(),
                connection.cursor() as cursor,
            ):
                cursor.execute(statement, [entry.pk])
        assert AuditLog.objects.get(pk=entry.pk).action == "test.recorded"

    def test_raw_insert_is_allowed(self) -> None:
        with connection.cursor() as cursor:
            cursor.execute(INSERT_SQL, [uuid.uuid4(), "raw.inserted", "success"])
        assert AuditLog.objects.filter(action="raw.inserted").exists()

    @pytest.mark.parametrize(
        ("action", "outcome"),
        [("NoDots", "success"), ("bad..action", "success"), ("ok.action", "maybe")],
    )
    def test_constraints_reject_malformed_rows(self, action: str, outcome: str) -> None:
        with pytest.raises(IntegrityError), transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(INSERT_SQL, [uuid.uuid4(), action, outcome])

    def test_trigger_is_installed_and_enabled(self) -> None:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT tgenabled FROM pg_trigger WHERE tgname = %s",
                [privileges.APPEND_ONLY_TRIGGER],
            )
            assert cursor.fetchone() == ("O",)


# -------------------------------------------------------------------- runtime-role privileges
@pytest.mark.django_db(transaction=True)
class TestRuntimeRole:
    """Connects as the runtime role (the role the application serves requests as)."""

    def test_runtime_role_can_only_read_and_append(self, runtime_dsn: str) -> None:
        existing = _entry("test.committed")
        with psycopg.connect(runtime_dsn, autocommit=True) as conn:
            conn.execute(INSERT_SQL, [uuid.uuid4(), "runtime.inserted", "success"])
            assert conn.execute(
                "SELECT count(*) FROM audit_auditlog WHERE id = %s", [existing.pk]
            ).fetchone() == (1,)
            for statement, message in (
                ("UPDATE audit_auditlog SET action = 'tampered.event'", "permission denied"),
                ("DELETE FROM audit_auditlog", "permission denied"),
                ("TRUNCATE audit_auditlog", "permission denied"),
                (
                    "ALTER TABLE audit_auditlog DISABLE TRIGGER audit_auditlog_append_only",
                    "must be owner",
                ),
                ("DROP TABLE audit_auditlog", "must be owner"),
                ("CREATE TABLE runtime_owned (id int)", "permission denied"),
            ):
                with pytest.raises(psycopg.Error, match=message):
                    conn.execute(statement)
            # Ordinary tables stay writable for the application.
            conn.execute("UPDATE accounts_user SET full_name = full_name")
            role = conn.execute("SELECT current_user").fetchone()
        assert AuditLog.objects.get(pk=existing.pk).action == "test.committed"
        assert role is not None
        assert role[0] == privileges.runtime_role()

    def test_verify_command_accepts_the_runtime_role(self, runtime_dsn: str) -> None:
        result = subprocess.run(
            [sys.executable, "manage.py", "verify_runtime_privileges"],
            cwd=BACKEND_DIR,
            env={**os.environ, "DATABASE_URL": runtime_dsn},
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "OK: runtime role" in result.stdout

    def test_verify_flags_the_owner_role(self) -> None:
        problems = privileges.runtime_privilege_problems()
        assert any("owns" in problem for problem in problems)
        assert any("holds UPDATE" in problem for problem in problems)


@pytest.mark.django_db
class TestGrants:
    def test_unset_runtime_role_grants_nothing(self) -> None:
        with override_settings(DATABASE_RUNTIME_ROLE=None):
            assert privileges.grant_runtime_privileges() is False

    def test_migrating_as_the_runtime_role_is_refused(self) -> None:
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_user")
            current = cursor.fetchone()[0]
        with (
            override_settings(DATABASE_RUNTIME_ROLE=current),
            pytest.raises(ImproperlyConfigured, match="owner role"),
        ):
            privileges.grant_runtime_privileges()

    def test_unknown_runtime_role_is_refused(self) -> None:
        with (
            override_settings(DATABASE_RUNTIME_ROLE="no_such_role_aems"),
            pytest.raises(ImproperlyConfigured, match="does not exist"),
        ):
            privileges.grant_runtime_privileges()

    def test_verify_command_reports_problems(self) -> None:
        from django.core.management import CommandError, call_command  # noqa: PLC0415

        with pytest.raises(CommandError, match="unsafe"):
            call_command("verify_runtime_privileges")


@pytest.mark.django_db(transaction=True)
def test_audit_migrations_are_reversible() -> None:
    executor = MigrationExecutor(connection)
    executor.migrate([("audit", None)])
    assert "audit_auditlog" not in connection.introspection.table_names()
    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate(executor.loader.graph.leaf_nodes())
    assert "audit_auditlog" in connection.introspection.table_names()
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT 1 FROM pg_trigger WHERE tgname = %s", [privileges.APPEND_ONLY_TRIGGER]
        )
        assert cursor.fetchone() == (1,)


@pytest.mark.django_db
class TestVerificationFindsEachProblem:
    """Each unsafe condition is reported (manipulations roll back with the test transaction)."""

    def test_disabled_trigger(self) -> None:
        with connection.cursor() as cursor:
            cursor.execute("ALTER TABLE audit_auditlog DISABLE TRIGGER audit_auditlog_append_only")
        assert any("disabled" in p for p in privileges.runtime_privilege_problems())

    def test_missing_table(self) -> None:
        with connection.cursor() as cursor:
            cursor.execute("ALTER TABLE audit_auditlog RENAME TO audit_auditlog_moved")
        problems = privileges.runtime_privilege_problems()
        assert any("does not exist" in p for p in problems)

    def test_missing_insert_privilege(self) -> None:
        with connection.cursor() as cursor:
            cursor.execute("REVOKE INSERT ON audit_auditlog FROM CURRENT_USER")
        assert any("lacks INSERT" in p for p in privileges.runtime_privilege_problems())

    def test_superuser(self, monkeypatch: pytest.MonkeyPatch) -> None:
        answers = iter([("someone", True, False), None])

        class StubCursor:
            def __enter__(self) -> "StubCursor":
                return self

            def __exit__(self, *exc: object) -> None:
                return None

            def execute(self, *args: object) -> None:
                return None

            def fetchone(self) -> object:
                return next(answers)

        class StubConnection:
            def cursor(self) -> StubCursor:
                return StubCursor()

        monkeypatch.setattr(privileges, "connections", {"default": StubConnection()})
        problems = privileges.runtime_privilege_problems()
        assert any("superuser" in p for p in problems)
        assert any("does not exist" in p for p in problems)


def test_model_string_and_text_guard() -> None:
    from apps.audit.redaction import AuditDataError, _text  # noqa: PLC0415

    assert str(AuditLog(action="a.b", outcome="success")).startswith("a.b (success)")
    with pytest.raises(AuditDataError):
        _text(123)
