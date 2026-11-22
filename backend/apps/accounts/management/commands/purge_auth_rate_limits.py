"""Delete expired authentication rate-limit counters and backoff records."""

from typing import Any

from django.core.management.base import BaseCommand

from apps.accounts.ratelimit import purge_expired


class Command(BaseCommand):
    help = "Delete expired AuthRateLimit counters and AuthBackoff records."

    def handle(self, *args: Any, **options: Any) -> None:
        counters, backoffs = purge_expired()
        self.stdout.write(
            f"Deleted {counters} rate-limit counter(s) and {backoffs} backoff record(s)."
        )
