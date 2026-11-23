"""Runtime database-role privileges (ADR-0006, ADR-0016).

AEMS uses two PostgreSQL roles:

- an **owner** role that owns the database objects and runs migrations;
- a **runtime** role that serves requests. It owns nothing, so it cannot ``ALTER`` tables,
  disable triggers or grant itself privileges.

After every ``migrate`` (``post_migrate``), :func:`grant_runtime_privileges` grants the runtime
role named by ``settings.DATABASE_RUNTIME_ROLE``:

- ``SELECT, INSERT, UPDATE, DELETE`` on every table, and usage of every sequence;
- on the audit table **only** ``SELECT, INSERT``: ``UPDATE, DELETE, TRUNCATE, REFERENCES`` and
  ``TRIGGER`` are revoked (from the runtime role and from ``PUBLIC``).

Running migrations *as* the runtime role is refused, because the runtime role would then own the
new tables. :func:`runtime_privilege_problems` inspects the connected role (used by
``manage.py verify_runtime_privileges`` and the tests).

Limits: these privileges and the append-only trigger stop the application and anyone holding only
the runtime credentials. The table owner, a superuser or any role with ``BYPASSRLS``/ownership can
still disable the trigger or rewrite rows; protecting history from database administrators needs
external controls (restricted owner credentials, backups, log shipping), not application code.
"""

from typing import Any

import structlog
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import connections
from psycopg import sql

logger = structlog.get_logger(__name__)

AUDIT_TABLE = "audit_auditlog"
APPEND_ONLY_TRIGGER = "audit_auditlog_append_only"
_AUDIT_FORBIDDEN = ("UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")


def runtime_role() -> str | None:
    role = getattr(settings, "DATABASE_RUNTIME_ROLE", None)
    return role or None


def grant_runtime_privileges(using: str = "default") -> bool:
    """Grant the runtime role its privileges in the current database. Returns False if unset."""
    role = runtime_role()
    if role is None:
        logger.warning(
            "audit.runtime_role_not_configured",
            detail="DJANGO_DB_RUNTIME_ROLE is unset: no runtime privileges were granted.",
        )
        return False
    connection = connections[using]
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_user")
        current = cursor.fetchone()[0]
        if current == role:
            msg = (
                f"Migrations are running as the runtime role {role!r}. Run them as the owner role "
                "(DATABASE_URL of the owner) so the runtime role owns no tables."
            )
            raise ImproperlyConfigured(msg)
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [role])
        if cursor.fetchone() is None:
            msg = f"The runtime database role {role!r} does not exist."
            raise ImproperlyConfigured(msg)
        ident = sql.Identifier(role)
        statements = [
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(connection.settings_dict["NAME"]), ident
            ),
            sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(ident),
            sql.SQL(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}"
            ).format(ident),
            sql.SQL("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}").format(ident),
            sql.SQL("REVOKE {} ON TABLE {} FROM {}, PUBLIC").format(
                sql.SQL(", ").join(sql.SQL(p) for p in _AUDIT_FORBIDDEN),
                sql.Identifier(AUDIT_TABLE),
                ident,
            ),
        ]
        for statement in statements:
            cursor.execute(statement)
    logger.info("audit.runtime_privileges_granted", role=role)
    return True


def grant_runtime_privileges_after_migrate(using: str = "default", **kwargs: Any) -> None:
    grant_runtime_privileges(using)


def runtime_privilege_problems(using: str = "default") -> list[str]:
    """Problems with the *connected* role as a runtime role (empty list means compliant)."""
    problems: list[str] = []
    with connections[using].cursor() as cursor:
        cursor.execute(
            "SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
        )
        user, is_super, bypass_rls = cursor.fetchone()
        if is_super or bypass_rls:
            problems.append(f"{user} is a superuser or bypasses row-level security.")
        cursor.execute(
            "SELECT pg_has_role(current_user, tableowner, 'USAGE') FROM pg_tables "
            "WHERE schemaname = 'public' AND tablename = %s",
            [AUDIT_TABLE],
        )
        row = cursor.fetchone()
        if row is None:
            return [*problems, f"Table {AUDIT_TABLE} does not exist (run migrations)."]
        if row[0]:
            problems.append(f"{user} owns (or is a member of the owner of) {AUDIT_TABLE}.")
        for privilege in ("SELECT", "INSERT"):
            if not _has_privilege(cursor, privilege):
                problems.append(f"{user} lacks {privilege} on {AUDIT_TABLE}.")
        for privilege in _AUDIT_FORBIDDEN:
            if _has_privilege(cursor, privilege):
                problems.append(f"{user} holds {privilege} on {AUDIT_TABLE}.")
        cursor.execute(
            "SELECT tgenabled FROM pg_trigger WHERE tgname = %s AND tgrelid = %s::regclass",
            [APPEND_ONLY_TRIGGER, AUDIT_TABLE],
        )
        trigger = cursor.fetchone()
        if trigger is None or trigger[0] == "D":
            problems.append(f"Append-only trigger {APPEND_ONLY_TRIGGER} is missing or disabled.")
    return problems


def _has_privilege(cursor: Any, privilege: str) -> bool:
    cursor.execute("SELECT has_table_privilege(current_user, %s, %s)", [AUDIT_TABLE, privilege])
    return bool(cursor.fetchone()[0])
