"""Deliver queued password-reset emails (ADR-0014).

Run it regularly from an external scheduler (for example every minute). Each run is bounded and
safe to run concurrently with other runs. Without it, reset requests are accepted but no email is
ever sent.

Output is counts only: never addresses, user ids, tokens or message bodies.
"""

import json
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from apps.accounts.outbox import deliver_due, outbox_settings, queue_status

DEFAULT_BATCH_SIZE = 100


class Command(BaseCommand):
    help = "Send due password-reset emails from the outbox (bounded, concurrency-safe)."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--batch-size",
            type=int,
            default=DEFAULT_BATCH_SIZE,
            help=f"Maximum messages to attempt in this run (default {DEFAULT_BATCH_SIZE}).",
        )
        parser.add_argument(
            "--status",
            action="store_true",
            help="Print queue counts as JSON and exit without sending.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        if options["status"]:
            self.stdout.write(json.dumps(queue_status(), sort_keys=True))
            return
        batch_size: int = options["batch_size"]
        maximum = outbox_settings().max_batch_size
        if not 1 <= batch_size <= maximum:
            msg = f"--batch-size must be between 1 and {maximum}."
            raise CommandError(msg)
        try:
            report = deliver_due(batch_size=batch_size)
        except ValueError as exc:  # configuration errors only; delivery failures are recorded
            raise CommandError(str(exc)) from exc
        self.stdout.write(" ".join(f"{key}={value}" for key, value in report.as_dict().items()))
