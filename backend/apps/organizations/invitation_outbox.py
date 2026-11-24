"""Invitation email outbox: queued with the invitation, sent by a command (ADR-0018, ADR-0014).

Creating an invitation inserts an ``InvitationEmail`` row in the same transaction, so a committed
invitation always has its delivery queued and a rolled-back one never sends email. No SMTP
connection is made inside a request or a database transaction.

``deliver_due`` (``manage.py deliver_invitation_emails``):

1. Claim one due row at a time (``SELECT … FOR UPDATE SKIP LOCKED``) under a lease, in a short
   transaction that commits before any network I/O.
2. Check the invitation is still deliverable: pending, unexpired, organization in the right
   state. Otherwise the row is cancelled (``invitation.delivery_cancelled``).
3. Issue the token: generate 256 random bits and store only their SHA-256 digest on the
   invitation, in a transaction that also confirms this worker still holds the lease. A previous
   attempt's token (if any) stops working: only the latest email's link is valid.
4. Send the email (organization name, link with the token in the URL fragment, expiry, how to
   sign in or create an account), then record the outcome with a compare-and-set on the lease.
5. On failure, store a sanitized category only and retry with exponential backoff, up to
   ``max_attempts``; a refused recipient fails at once.

"Delivered" means the SMTP server accepted the message, never merely queued. Delivery is at least
once: a crash after sending but before recording leads to a resend with a new token, which
invalidates the earlier link. The outbox row stores no address, token, link or message body.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.core.mail import send_mail
from django.db import transaction
from django.db.models import Count, Q
from django.utils import timezone

from apps.accounts.outbox import (
    PERMANENT_FAILURES,
    Clock,
    DeliveryReport,
    FailureCategory,
    Outcome,
    categorize,
)
from apps.audit import services as audit

from . import invitations
from .models import (
    Invitation,
    InvitationEmail,
    InvitationEmailStatus,
    InvitationStatus,
    OrganizationStatus,
)

Status = InvitationEmailStatus


@dataclass(frozen=True)
class OutboxSettings:
    max_attempts: int
    backoff_base: timedelta
    backoff_cap: timedelta
    lease: timedelta
    max_batch_size: int


def outbox_settings() -> OutboxSettings:
    c = settings.INVITATION_OUTBOX
    return OutboxSettings(
        max_attempts=c["max_attempts"],
        backoff_base=timedelta(seconds=c["backoff_base_seconds"]),
        backoff_cap=timedelta(seconds=c["backoff_cap_seconds"]),
        lease=timedelta(seconds=c["lease_seconds"]),
        max_batch_size=c["max_batch_size"],
    )


def claim_next(now: datetime, *, lease: timedelta) -> InvitationEmail | None:
    with transaction.atomic():
        row = (
            InvitationEmail.objects.select_for_update(skip_locked=True)
            .filter(status=Status.PENDING, next_attempt_at__lte=now)
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


def _event(row: InvitationEmail, invitation: Invitation, action: str, **metadata: Any) -> None:
    audit.record(
        action,
        outcome="success" if action.endswith("delivered") else "failure",
        organization=invitation.organization,
        target_type="invitation",
        target_id=invitation.pk,
        metadata={"outbox_id": row.pk, "attempt": row.attempts, **metadata},
    )


def _finish(
    row: InvitationEmail,
    invitation: Invitation,
    action: str,
    metadata: dict[str, Any] | None = None,
    **fields: Any,
) -> bool:
    """Compare-and-set on the lease; the outcome and its audit record share one transaction."""
    with transaction.atomic():
        updated = InvitationEmail.objects.filter(
            pk=row.pk, claim_id=row.claim_id, status=Status.PENDING
        ).update(claim_id=None, claimed_until=None, **fields)
        if updated != 1:
            return False
        _event(row, invitation, action, **(metadata or {}))
    return True


def _undeliverable_reason(invitation: Invitation, now: datetime) -> str | None:
    if invitation.status != InvitationStatus.PENDING:
        return "not_pending"
    if invitation.expires_at <= now:
        return "expired"
    expected = (
        OrganizationStatus.PROVISIONING
        if invitation.is_initial_owner
        else OrganizationStatus.ACTIVE
    )
    if invitation.organization.status != expected:
        return "organization_unavailable"
    return None


def _issue_token(row: InvitationEmail, invitation: Invitation, now: datetime) -> str | None:
    """Store the digest of a fresh token if this worker still holds the lease. Returns the token."""
    token = invitations.new_token()
    with transaction.atomic():
        held = (
            InvitationEmail.objects.select_for_update()
            .filter(pk=row.pk, claim_id=row.claim_id, status=Status.PENDING)
            .exists()
        )
        if not held:
            return None
        issued = Invitation.objects.filter(
            pk=invitation.pk, status=InvitationStatus.PENDING, expires_at__gt=now
        ).update(token_hash=invitations.hash_token(token), token_issued_at=now, updated_at=now)
    return token if issued == 1 else ""


def _clean(text: str) -> str:
    return "".join(ch for ch in text if ch.isprintable()).strip()


def _send(invitation: Invitation, token: str) -> None:
    organization = _clean(invitation.organization.name)
    # The token travels in the URL fragment, which browsers never send to servers or in Referer.
    link = settings.INVITATION_URL_TEMPLATE.format(token=token)
    role = "the Owner of" if invitation.is_initial_owner else "a member of"
    expires = invitation.expires_at.strftime("%Y-%m-%d %H:%M UTC")
    send_mail(
        subject=f"You are invited to join {organization} on AEMS",
        message=(
            f"You have been invited to become {role} {organization} on AEMS.\n\n"
            f"Accept the invitation here:\n{link}\n\n"
            f"The link expires on {expires} and can be used once. Treat it like a password: "
            "anyone with the link can accept the invitation for this email address.\n\n"
            "If you already have an AEMS account with this email address, sign in to accept. "
            "Otherwise you can create your account from the link. AEMS never asks for your "
            "password by email.\n\n"
            "If you were not expecting this invitation, you can ignore this email.\n"
        ),
        from_email=None,
        recipient_list=[invitation.email],
        fail_silently=False,
    )


def deliver_claimed(row: InvitationEmail, *, clock: Clock, config: OutboxSettings) -> Outcome:
    invitation = Invitation.objects.select_related("organization").get(pk=row.invitation_id)
    reason = _undeliverable_reason(invitation, clock())
    if reason is not None:
        return _terminal(row, invitation, Status.CANCELLED, Outcome.CANCELLED, clock, reason)
    token = _issue_token(row, invitation, clock())
    if token is None:
        return _lease_lost(row, invitation)
    if not token:  # the invitation changed state between the check and the update
        return _terminal(row, invitation, Status.CANCELLED, Outcome.CANCELLED, clock, "not_pending")
    try:
        _send(invitation, token)
    except Exception as exc:
        # Broad on purpose: any failure is recorded and retried or failed, never propagated.
        # Only the category is kept: messages can contain the recipient address.
        return _record_failure(row, invitation, categorize(exc), clock=clock, config=config)
    now = clock()
    if not _finish(
        row,
        invitation,
        "invitation.email_delivered",
        status=Status.DELIVERED,
        delivered_at=now,
        completed_at=now,
        last_failure="",
    ):
        return _lease_lost(row, invitation)
    return Outcome.DELIVERED


def _terminal(  # noqa: PLR0917 - internal helper, every argument is required
    row: InvitationEmail,
    invitation: Invitation,
    status: str,
    outcome: Outcome,
    clock: Clock,
    reason: str,
) -> Outcome:
    if not _finish(
        row,
        invitation,
        "invitation.delivery_cancelled",
        {"reason": reason},
        status=status,
        completed_at=clock(),
        last_failure=reason,
    ):
        return _lease_lost(row, invitation)
    return outcome


def _record_failure(
    row: InvitationEmail,
    invitation: Invitation,
    category: FailureCategory,
    *,
    clock: Clock,
    config: OutboxSettings,
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
        invitation,
        "invitation.delivery_failed",
        {"category": category.value, "retry_scheduled": not final},
        last_failure=category.value,
        **fields,
    ):
        return _lease_lost(row, invitation)
    return Outcome.FAILED if final else Outcome.RETRY_SCHEDULED


def _lease_lost(row: InvitationEmail, invitation: Invitation) -> Outcome:
    audit.record_security_event(
        "invitation.delivery_lease_lost",
        organization=invitation.organization,
        target_type="invitation",
        target_id=invitation.pk,
        metadata={"outbox_id": row.pk, "attempt": row.attempts},
    )
    return Outcome.LEASE_LOST


def deliver_due(*, batch_size: int, clock: Clock = timezone.now) -> DeliveryReport:
    """One bounded run: deliver up to ``batch_size`` invitation emails."""
    config = outbox_settings()
    if not 1 <= batch_size <= config.max_batch_size:
        msg = f"batch_size must be between 1 and {config.max_batch_size}."
        raise ValueError(msg)
    if config.lease.total_seconds() <= settings.EMAIL_TIMEOUT:
        msg = "INVITATION_OUTBOX lease_seconds must exceed EMAIL_TIMEOUT."
        raise ValueError(msg)
    report = DeliveryReport()
    for _ in range(batch_size):
        row = claim_next(clock(), lease=config.lease)
        if row is None:
            break
        report.claimed += 1
        report.count(deliver_claimed(row, clock=clock, config=config))
    return report


def queue_status() -> dict[str, Any]:
    """Counts only: no invitation ids, addresses or tokens."""
    by_status = dict(
        InvitationEmail.objects.values_list("status")
        .annotate(n=Count("id"))
        .values_list("status", "n")
    )
    return {s.value: by_status.get(s.value, 0) for s in Status}
