"""Fail if Django's default user tables exist.

Guards ADR-0002: ``AUTH_USER_MODEL = "accounts.User"`` was set before the first auth migration, so
Django's default ``auth_user`` table (and its M2M tables) must never be created. The
``auth_group`` / ``auth_permission`` tables are expected (used by PermissionsMixin and the admin).
Used by CI after a fresh migrate.
"""

from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import connection

FORBIDDEN_TABLES = ("auth_user", "auth_user_groups", "auth_user_user_permissions")


class Command(BaseCommand):
    help = "Fail if Django's default auth_user tables exist."

    def handle(self, *args: Any, **options: Any) -> None:
        tables = sorted(set(connection.introspection.table_names()) & set(FORBIDDEN_TABLES))
        if tables:
            msg = f"Unexpected default Django user tables present: {', '.join(tables)}"
            raise CommandError(msg)
        self.stdout.write("OK: no default auth_user tables (custom user model: accounts.User)")
