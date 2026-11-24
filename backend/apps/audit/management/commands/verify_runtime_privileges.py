"""Check that the connected database role is a proper runtime role for the audit log.

Run it with the runtime ``DATABASE_URL`` (the role the application serves requests as). It fails
if that role is a superuser, owns the audit table, lacks ``SELECT``/``INSERT`` on it, holds
``UPDATE``/``DELETE``/``TRUNCATE`` on it, or if the append-only trigger is missing or disabled.
"""

from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.audit.privileges import runtime_privilege_problems


class Command(BaseCommand):
    help = "Verify the connected role's audit-table privileges and the append-only trigger."

    def handle(self, *args: Any, **options: Any) -> None:
        problems = runtime_privilege_problems()
        if problems:
            raise CommandError(
                "Runtime database privileges are unsafe:\n- " + "\n- ".join(problems)
            )
        self.stdout.write("OK: runtime role can only read and append audit records.")
