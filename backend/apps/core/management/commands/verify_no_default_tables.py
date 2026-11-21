"""Fail if Django's default auth/admin/session/contenttypes tables exist.

Guards ADR-0002: the custom user model (Batch 3) must be the first user-related migration, so a
default ``auth_user`` table must never be created beforehand. Used by CI after a fresh migrate.
"""

from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import connection

FORBIDDEN_TABLE_PREFIXES = ("auth_", "django_admin", "django_session", "django_content_type")


class Command(BaseCommand):
    help = "Fail if default Django auth/admin/session/contenttypes tables exist."

    def handle(self, *args: Any, **options: Any) -> None:
        tables = sorted(
            name
            for name in connection.introspection.table_names()
            if name.startswith(FORBIDDEN_TABLE_PREFIXES)
        )
        if tables:
            msg = f"Unexpected default Django tables present: {', '.join(tables)}"
            raise CommandError(msg)
        self.stdout.write("OK: no default auth/admin/session/contenttypes tables")
