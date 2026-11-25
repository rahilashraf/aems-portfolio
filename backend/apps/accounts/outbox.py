"""Password-reset email outbox: enqueue in the request, deliver from a command (ADR-0014).

This is deliberately **not** a general job queue. It stores one kind of work: "send this user a
password-reset email".

Request path (``enqueue_password_reset``)
    One SQL statement for every submitted address. ``INSERT … SELECT … FROM accounts_user`` inserts
    a row only when an active user with a usable password has that address. Unknown or ineligible
    addresses match nothing, so no row is written. The statement shape and round trip are the same
    either way, and no SMTP connection is made. ``ON CONFLICT`` on the partial unique index (one
    pending row per user) refreshes the existing pending row instead of adding another.

Delivery (``deliver_due``, run by ``manage.py deliver_password_reset_emails``)
    1. Mark pending rows past ``expires_at`` as expired.
    2. Claim one due row at a time in a short transaction (``SELECT … FOR UPDATE SKIP LOCKED``),
       giving it a lease (``claim_id`` + ``claimed_until``) and counting the attempt. The
       transaction commits **before** any network I/O, so no row lock is held during SMTP.
    3. Re-check eligibility: the user is active with a usable password, and the password has not
       changed since the request.
    4. Generate the reset token from the user's *current* state, send it to the user's *current*
       address, and record the outcome. The outcome is written only if this worker still holds the
       lease (compare-and-set on ``claim_id``).
    5. Delete finished rows older than the retention period.

Delivery is **at least once**. A crash after the SMTP server accepted a message, but before the
row was marked delivered, leaves the lease to expire, and the message is sent again with a fresh
token. Duplicates are bounded by ``max_attempts`` and ``ttl_seconds``. Every copy is an ordinary
reset token: it expires after ``PASSWORD_RESET_TIMEOUT``, and using any one of them changes the
password, which invalidates all the others.
"""

import smtplib
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from django.conf import settings
from django.contrib.auth.hashers import UNUSABLE_PASSWORD_PREFIX
from django.core.mail import send_mail
from django.db import connection, transaction
from django.db.models import Count, Min, Q
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from apps.audit import services as audit

from .models import PasswordResetDeliveryStatus as Status
from .models import PasswordResetOutbox, User
from .tokens import password_reset_tokens

Clock = Callable[[], datetime]

# Literal SQL (no interpolation); the table names are asserted against the models in tests.
OUTBOX_TABLE = "accounts_passwordresetoutbox"
USER_TABLE = "accounts_user"
# ``lower(u.email)`` uses the functional unique index; stored emails are already normalized.
# The ON CONFLICT target and predicate match the partial unique index on (user_id) WHERE pending.
_ENQUEUE_SQL = """
    INSERT INTO accounts_passwordresetoutbox
        (id, user_id, requested_at, expires_at, status, attempts, next_attempt_at, last_failure)
    SELECT %s, u.id, %s, %s, 'pending', 0, %s, ''
    FROM accounts_user AS u
    WHERE lower(u.email) = %s AND u.is_active AND left(u.password, 1) <> %s
    ON CONFLICT (user_id) WHERE status = 'pending'
    DO UPDATE SET requested_at = EXCLUDED.requested_at, expires_at = EXCLUDED.expires_at
    RETURNING user_id
"""


@dataclass(frozen=True)
class OutboxSettings:
    ttl: timedelta
    max_attempts: int
    backoff_base: timedelta
    backoff_cap: timedelta
    lease: timedelta
    retention: timedelta
    max_batch_size: int


def outbox_settings() -> OutboxSettings:
    c = settings.PASSWORD_RESET_OUTBOX
    return OutboxSettings(
        ttl=timedelta(seconds=c["ttl_seconds"]),
        max_attempts=c["max_attempts"],
        backoff_base=timedelta(seconds=c["backoff_base_seconds"]),
        backoff_cap=timedelta(seconds=c["backoff_cap_seconds"]),
        lease=timedelta(seconds=c["lease_seconds"]),
        retention=timedelta(seconds=c["retention_seconds"]),
        max_batch_size=c["max_batch_size"],
    )


# ----------------------------------------------------------------------------------- enqueue
def enqueue_password_reset(normalized_email: str, *, now: datetime | None = None) -> str | None:
    """Queue a reset email if an eligible account has this address; return its user id or None.

    Identical database work for known and unknown addresses: one statement, no SMTP. The return
    value is used only for the server-side security event, never for the HTTP response.
    """
    now = now or timezone.now()
    expires_at = now + outbox_settings().ttl
    with connection.cursor() as cursor:
        cursor.execute(
            _ENQUEUE_SQL,
            [uuid.uuid4(), now, expires_at, now, normalized_email, UNUSABLE_PASSWORD_PREFIX],
        )
        row = cursor.fetchone()
    return str(row[0]) if row else None


# ---------------------------------------------------------------------------------- delivery
class FailureCategory(StrEnum):
    """Sanitized failure categories: stored and logged instead of exception messages."""

    RECIPIENT_REFUSED = "recipient_refused"
    SMTP_AUTHENTICATION = "smtp_authentication"
    CONNECTION = "connection"
    TIMEOUT = "timeout"
    SMTP_ERROR = "smtp_error"
    NETWORK = "network"
    UNEXPECTED = "unexpected"
    # Claimed more than ``max_attempts`` times without an outcome being recorded: earlier runs
    # stopped mid-delivery (crash, timeout, kill). Never retried again (AEMS-024).
    ABANDONED = "abandoned"


# Failures that retrying cannot fix: the server rejected the recipient, or the attempt budget was
# spent by runs that never recorded an outcome.
PERMANENT_FAILURES = frozenset({FailureCategory.RECIPIENT_REFUSED, FailureCategory.ABANDONED})


def attempts_exhausted(attempts: int, max_attempts: int) -> bool:
    """A claim beyond the budget: earlier claims ended without an outcome (AEMS-024).

    Every claim increments ``attempts`` before sending, and only a recorded failure enforces
    ``max_attempts``. A worker that dies after claiming (or after sending) records nothing, so
    without this check the row would be reclaimed after every lease, without limit.
    """
    return attempts > max_attempts


# First match wins: subclasses before their bases (SMTPException and ConnectionError are OSErrors).
_CATEGORY_BY_TYPE: tuple[
    tuple[type[BaseException] | tuple[type[BaseException], ...], FailureCategory], ...
] = (
    (smtplib.SMTPRecipientsRefused, FailureCategory.RECIPIENT_REFUSED),
    (smtplib.SMTPAuthenticationError, FailureCategory.SMTP_AUTHENTICATION),
    (
        (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, ConnectionError),
        FailureCategory.CONNECTION,
    ),
    (smtplib.SMTPException, FailureCategory.SMTP_ERROR),
    (OSError, FailureCategory.NETWORK),
)


def categorize(exc: BaseException) -> FailureCategory:
    # smtplib turns socket timeouts during a reply into SMTPServerDisconnected (chained).
    if isinstance(exc, TimeoutError) or isinstance(exc.__context__, TimeoutError):
        return FailureCategory.TIMEOUT
    for types, category in _CATEGORY_BY_TYPE:
        if isinstance(exc, types):
            return category
    return FailureCategory.UNEXPECTED


class Outcome(StrEnum):
    DELIVERED = "delivered"
    RETRY_SCHEDULED = "retry_scheduled"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    LEASE_LOST = "lease_lost"


@dataclass
class DeliveryReport:
    claimed: int = 0
    expired: int = 0
    purged: int = 0
    outcomes: dict[str, int] = field(default_factory=dict)

    def count(self, outcome: Outcome) -> None:
        self.outcomes[outcome.value] = self.outcomes.get(outcome.value, 0) + 1

    def as_dict(self) -> dict[str, int]:
        return {
            "claimed": self.claimed,
            **{o.value: self.outcomes.get(o.value, 0) for o in Outcome},
            "expired_unclaimed": self.expired,
            "purged": self.purged,
        }


def _audit_fields(row: PasswordResetOutbox, **metadata: Any) -> dict[str, Any]:
    """The subject is the user; no actor (the delivery command acts for the system)."""
    return {
        "target_type": "user",
        "target_id": row.user_id,
        "metadata": {"outbox_id": row.id, "attempt": row.attempts, **metadata},
    }


def _outcome_of(event: str) -> Any:
    return "success" if event.endswith("delivered") else "failure"


def expire_overdue(now: datetime) -> int:
    """Mark unclaimed pending rows past their expiry as expired (never sent)."""
    with transaction.atomic():
        rows = list(
            PasswordResetOutbox.objects.select_for_update(skip_locked=True)
            .filter(status=Status.PENDING, expires_at__lte=now)
            .filter(Q(claimed_until__isnull=True) | Q(claimed_until__lte=now))
        )
        PasswordResetOutbox.objects.filter(pk__in=[r.pk for r in rows]).update(
            status=Status.EXPIRED, completed_at=now, claim_id=None, claimed_until=None
        )
        for row in rows:  # same transaction as the status change
            audit.record(
                "auth.password_reset.delivery_expired", outcome="failure", **_audit_fields(row)
            )
    return len(rows)


def claim_next(now: datetime, *, lease: timedelta) -> PasswordResetOutbox | None:
    """Claim one due row under a lease. The lock lasts only for this short transaction."""
    with transaction.atomic():
        row = (
            PasswordResetOutbox.objects.select_for_update(skip_locked=True)
            .filter(status=Status.PENDING, next_attempt_at__lte=now, expires_at__gt=now)
            .filter(Q(claimed_until__isnull=True) | Q(claimed_until__lte=now))
            .order_by("next_attempt_at", "id")
            .first()
        )
        if row is None:
            return None
        row.claim_id = uuid.uuid4()
        row.claimed_until = now + lease
        row.attempts += 1
        row.last_attempt_at = now
        row.save(update_fields=["claim_id", "claimed_until", "attempts", "last_attempt_at"])
    return row


def _finish(
    row: PasswordResetOutbox, event: str, metadata: dict[str, Any] | None = None, **fields: Any
) -> bool:
    """Record an outcome only if this worker still holds the lease (compare-and-set).

    The status change and its audit record share one transaction.
    """
    with transaction.atomic():
        updated = PasswordResetOutbox.objects.filter(
            pk=row.pk, claim_id=row.claim_id, status=Status.PENDING
        ).update(claim_id=None, claimed_until=None, **fields)
        if updated != 1:
            return False
        audit.record(event, outcome=_outcome_of(event), **_audit_fields(row, **(metadata or {})))
    return True


def _send(user: User) -> None:
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = password_reset_tokens.make_token(user)
    # The token travels in the URL fragment, which browsers never send to servers or in Referer.
    link = settings.PASSWORD_RESET_URL_TEMPLATE.format(uid=uid, token=token)
    send_mail(
        subject="Reset your AEMS password",
        message=(
            f"Hello {user.full_name},\n\n"
            "A password reset was requested for your AEMS account. Use the link below to choose a "
            "new password. The link expires and can only be used once.\n\n"
            f"{link}\n\n"
            "If you did not request this, you can ignore this email; your password is unchanged.\n"
        ),
        from_email=None,
        recipient_list=[user.email],
        fail_silently=False,
    )


def _ineligibility(row: PasswordResetOutbox, user: User | None) -> str | None:
    if user is None or not user.is_active or not user.has_usable_password():
        return "account_ineligible"
    changed = user.password_changed_at
    if changed is not None and changed > row.requested_at:
        # The password changed after the request (e.g. another reset completed): a link made now
        # would still work, but the request it answers is obsolete.
        return "superseded"
    return None


def deliver_claimed(row: PasswordResetOutbox, *, clock: Clock, config: OutboxSettings) -> Outcome:
    if attempts_exhausted(row.attempts, config.max_attempts):
        return _record_failure(row, FailureCategory.ABANDONED, clock=clock, config=config)
    user = User.objects.filter(pk=row.user_id).first()
    reason = _ineligibility(row, user)
    if user is None or reason is not None:
        return _finish_terminal(
            row,
            Outcome.CANCELLED,
            "auth.password_reset.delivery_cancelled",
            clock=clock,
            reason=reason or "account_ineligible",
        )
    if row.expires_at <= clock():
        return _finish_terminal(
            row, Outcome.EXPIRED, "auth.password_reset.delivery_expired", clock=clock
        )
    try:
        _send(user)
    except Exception as exc:
        # Broad on purpose: any failure is recorded and retried or failed, never propagated. Only
        # the category is kept; the message can contain the recipient address.
        return _record_failure(row, categorize(exc), clock=clock, config=config)

    now = clock()
    if not _finish(
        row,
        "auth.password_reset.email_delivered",
        status=Status.DELIVERED,
        delivered_at=now,
        completed_at=now,
        last_failure="",
    ):
        return _lease_lost(row)
    return Outcome.DELIVERED


_TERMINAL_STATUS = {Outcome.CANCELLED: Status.CANCELLED, Outcome.EXPIRED: Status.EXPIRED}


def _finish_terminal(
    row: PasswordResetOutbox, outcome: Outcome, event: str, *, clock: Clock, reason: str = ""
) -> Outcome:
    if not _finish(
        row,
        event,
        {"reason": reason} if reason else None,
        status=_TERMINAL_STATUS[outcome],
        completed_at=clock(),
        last_failure=reason,
    ):
        return _lease_lost(row)
    return outcome


def _record_failure(
    row: PasswordResetOutbox, category: FailureCategory, *, clock: Clock, config: OutboxSettings
) -> Outcome:
    now = clock()
    final = category in PERMANENT_FAILURES or row.attempts >= config.max_attempts
    if final:
        fields: dict[str, Any] = {"status": Status.FAILED, "completed_at": now}
    else:
        delay = min(config.backoff_base * 2 ** (row.attempts - 1), config.backoff_cap)
        fields = {"next_attempt_at": now + delay}
    if not _finish(
        row,
        "auth.password_reset.delivery_failed",
        {"category": category.value, "retry_scheduled": not final},
        last_failure=category.value,
        **fields,
    ):
        return _lease_lost(row)
    return Outcome.FAILED if final else Outcome.RETRY_SCHEDULED


def _lease_lost(row: PasswordResetOutbox) -> Outcome:
    # Another run reclaimed the row after our lease expired; its outcome wins.
    audit.record_security_event("auth.password_reset.delivery_lease_lost", **_audit_fields(row))
    return Outcome.LEASE_LOST


def purge_finished(now: datetime, *, retention: timedelta) -> int:
    deleted, _ = (
        PasswordResetOutbox.objects.exclude(status=Status.PENDING)
        .filter(completed_at__lt=now - retention)
        .delete()
    )
    return deleted


def deliver_due(*, batch_size: int, clock: Clock = timezone.now) -> DeliveryReport:
    """One bounded run: expire, deliver up to ``batch_size`` messages, purge."""
    config = outbox_settings()
    if not 1 <= batch_size <= config.max_batch_size:
        msg = f"batch_size must be between 1 and {config.max_batch_size}."
        raise ValueError(msg)
    if config.lease.total_seconds() <= settings.EMAIL_TIMEOUT:
        msg = "PASSWORD_RESET_OUTBOX lease_seconds must exceed EMAIL_TIMEOUT."
        raise ValueError(msg)

    report = DeliveryReport(expired=expire_overdue(clock()))
    for _ in range(batch_size):
        row = claim_next(clock(), lease=config.lease)
        if row is None:
            break
        report.claimed += 1
        report.count(deliver_claimed(row, clock=clock, config=config))
    report.purged = purge_finished(clock(), retention=config.retention)
    return report


def queue_status(now: datetime | None = None) -> dict[str, Any]:
    """Counts only: no user ids, addresses or tokens."""
    now = now or timezone.now()
    by_status = dict(
        PasswordResetOutbox.objects.values_list("status")
        .annotate(n=Count("id"))
        .values_list("status", "n")
    )
    pending = PasswordResetOutbox.objects.filter(status=Status.PENDING)
    oldest = pending.aggregate(oldest=Min("requested_at"))["oldest"]
    failures = dict(
        PasswordResetOutbox.objects.exclude(last_failure="")
        .values_list("last_failure")
        .annotate(n=Count("id"))
        .values_list("last_failure", "n")
    )
    return {
        **{s.value: by_status.get(s.value, 0) for s in Status},
        "pending_due": pending.filter(next_attempt_at__lte=now, expires_at__gt=now).count(),
        "pending_claimed": pending.filter(claimed_until__gt=now).count(),
        "oldest_pending_age_seconds": int((now - oldest).total_seconds()) if oldest else 0,
        "last_failure_categories": failures,
    }
