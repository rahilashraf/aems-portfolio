"""Invitation email outbox: commit-safe queueing, token issuance at send time, retries,
cancellation, lease compare-and-set and the delivery command (ADR-0018)."""

import json
import smtplib
from collections.abc import Callable
from datetime import timedelta
from io import StringIO
from typing import Any

import pytest
from django.core import mail
from django.core.management import CommandError, call_command
from django.db import transaction
from django.utils import timezone

from apps.audit.models import AuditLog
from apps.organizations import invitation_outbox, invitations
from apps.organizations.models import (
    Invitation,
    InvitationEmail,
    InvitationEmailStatus,
    InvitationStatus,
    Organization,
    OrganizationStatus,
)
from apps.rbac.tests.conftest import Team

from .invitation_helpers import TOKEN_IN_LINK, deliver, preview

pytestmark = pytest.mark.django_db
EMAIL = "invitee@example.org"


@pytest.fixture
def invitation(team: Team) -> Invitation:
    return invitations.create_invitation(
        actor=team.owner, organization=team.org, email=EMAIL, role_ids=[team.auditors.pk]
    )


def outbox_row(invitation: Invitation) -> InvitationEmail:
    return InvitationEmail.objects.get(invitation=invitation)


def actions() -> list[str]:
    return list(AuditLog.objects.order_by("created_at", "id").values_list("action", flat=True))


def failing_send(exc: BaseException) -> Callable[..., None]:
    def send(*_args: Any, **_kwargs: Any) -> None:
        raise exc

    return send


def test_rolled_back_invitation_never_sends(team: Team) -> None:
    def invite_then_fail() -> None:
        with transaction.atomic():
            invitations.create_invitation(
                actor=team.owner, organization=team.org, email=EMAIL, role_ids=[team.auditors.pk]
            )
            raise RuntimeError("later step failed")

    with pytest.raises(RuntimeError):
        invite_then_fail()
    assert not InvitationEmail.objects.exists()
    assert deliver() == {}


def test_delivery_issues_a_token_and_stores_only_its_digest(invitation: Invitation) -> None:
    assert invitation.token_hash is None
    token = deliver()[EMAIL]
    invitation.refresh_from_db()
    assert invitation.token_hash == invitations.hash_token(token)
    assert invitation.token_issued_at is not None
    row = outbox_row(invitation)
    assert (row.status, row.attempts, row.last_failure) == ("delivered", 1, "")
    assert row.delivered_at is not None
    message = mail.outbox[-1]
    assert message.to == [EMAIL]
    link = TOKEN_IN_LINK.search(str(message.body))
    assert link is not None
    assert "#token=" in str(message.body)  # fragment: never sent to servers or in Referer
    assert "invitation.email_delivered" in actions()
    # The outbox row holds no address, token or link; a second run sends nothing.
    assert EMAIL not in json.dumps(list(InvitationEmail.objects.values()), default=str)
    assert deliver() == {}


@pytest.mark.parametrize(
    ("exc", "category"),
    [
        (smtplib.SMTPServerDisconnected("down"), "connection"),
        (TimeoutError(), "timeout"),
        (smtplib.SMTPAuthenticationError(535, b"invitee@example.org"), "smtp_authentication"),
        (OSError("network"), "network"),
        (ValueError(EMAIL), "unexpected"),
    ],
)
def test_transient_failures_retry_with_backoff(
    invitation: Invitation, monkeypatch: pytest.MonkeyPatch, exc: BaseException, category: str
) -> None:
    monkeypatch.setattr(invitation_outbox, "send_mail", failing_send(exc))
    report = invitation_outbox.deliver_due(batch_size=10)
    assert report.as_dict()["retry_scheduled"] == 1
    row = outbox_row(invitation)
    assert (row.status, row.last_failure, row.attempts) == ("pending", category, 1)
    assert row.next_attempt_at > timezone.now() + timedelta(seconds=50)
    failure = AuditLog.objects.get(action="invitation.delivery_failed")
    assert failure.metadata["category"] == category
    assert EMAIL not in json.dumps(failure.metadata)
    # The issued digest belongs to a token that was never delivered: still not previewable.
    assert Invitation.objects.get(pk=invitation.pk).token_hash is not None
    monkeypatch.undo()
    InvitationEmail.objects.filter(pk=row.pk).update(next_attempt_at=timezone.now())
    token = deliver()[EMAIL]
    assert preview(token).status_code == 200


def test_permanent_failure_and_attempt_limit(
    invitation: Invitation, monkeypatch: pytest.MonkeyPatch, settings: Any
) -> None:
    monkeypatch.setattr(
        invitation_outbox,
        "send_mail",
        failing_send(smtplib.SMTPRecipientsRefused({EMAIL: (550, b"no")})),
    )
    assert invitation_outbox.deliver_due(batch_size=10).as_dict()["failed"] == 1
    assert outbox_row(invitation).status == InvitationEmailStatus.FAILED
    # The invitation itself is unchanged; managers can revoke and invite again.
    assert Invitation.objects.get(pk=invitation.pk).status == InvitationStatus.PENDING

    settings.INVITATION_OUTBOX = {**settings.INVITATION_OUTBOX, "max_attempts": 1}
    other = invitations.create_invitation(
        actor=invitation.invited_by,
        organization=invitation.organization,
        email="second@example.org",
        role_ids=[r.pk for r in invitation.roles.all()],
    )
    monkeypatch.setattr(invitation_outbox, "send_mail", failing_send(TimeoutError()))
    invitation_outbox.deliver_due(batch_size=10)
    assert outbox_row(other).status == InvitationEmailStatus.FAILED


@pytest.mark.parametrize("change", ["revoked", "expired", "organization_suspended"])
def test_undeliverable_invitations_are_cancelled(
    invitation: Invitation, team: Team, change: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    reason = {"revoked": "not_pending", "expired": "expired"}.get(
        change, "organization_unavailable"
    )
    if change == "revoked":
        invitations.revoke_invitation(
            actor=team.owner, organization=team.org, invitation_id=invitation.pk
        )
    elif change == "expired":
        later = timezone.now() + timedelta(days=8)
        report = invitation_outbox.deliver_due(batch_size=10, clock=lambda: later)
        assert report.as_dict()["cancelled"] == 1
    else:
        Organization.objects.filter(pk=team.org.pk).update(status=OrganizationStatus.SUSPENDED)
    if change != "expired":
        assert deliver() == {}
    row = outbox_row(invitation)
    assert (row.status, row.last_failure) == ("cancelled", reason)
    assert mail.outbox == []
    assert AuditLog.objects.get(action="invitation.delivery_cancelled").metadata["reason"] == reason


def test_state_change_between_check_and_issue_cancels(
    invitation: Invitation, team: Team, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = invitation_outbox._undeliverable_reason

    def revoke_then_check(inv: Invitation, now: Any) -> Any:
        result = real(inv, now)
        Invitation.objects.filter(pk=inv.pk).update(
            status=InvitationStatus.REVOKED, revoked_at=timezone.now(), revoked_by=team.owner
        )
        return result

    monkeypatch.setattr(invitation_outbox, "_undeliverable_reason", revoke_then_check)
    assert invitation_outbox.deliver_due(batch_size=10).as_dict()["cancelled"] == 1
    assert mail.outbox == []


def test_lost_lease_is_detected(invitation: Invitation, monkeypatch: pytest.MonkeyPatch) -> None:
    real_send = invitation_outbox._send

    def steal_lease(inv: Invitation, token: str) -> None:
        InvitationEmail.objects.filter(invitation=inv).update(claim_id=None)
        real_send(inv, token)

    monkeypatch.setattr(invitation_outbox, "_send", steal_lease)
    assert invitation_outbox.deliver_due(batch_size=10).as_dict()["lease_lost"] == 1
    assert "invitation.delivery_lease_lost" in actions()

    # A lease lost before the token is issued sends nothing.
    other = invitations.create_invitation(
        actor=invitation.invited_by,
        organization=invitation.organization,
        email="second@example.org",
        role_ids=[r.pk for r in invitation.roles.all()],
    )
    real_claim = invitation_outbox.claim_next

    def claim_then_lose(*args: Any, **kwargs: Any) -> Any:
        row = real_claim(*args, **kwargs)
        if row is not None:
            InvitationEmail.objects.filter(pk=row.pk).update(claim_id=None)
        return row

    monkeypatch.setattr(invitation_outbox, "claim_next", claim_then_lose)
    sent = len(mail.outbox)
    assert invitation_outbox.deliver_due(batch_size=10).as_dict()["lease_lost"] == 1
    assert len(mail.outbox) == sent
    assert Invitation.objects.get(pk=other.pk).token_hash is None


def test_failure_after_lease_lost_is_discarded(
    invitation: Invitation, monkeypatch: pytest.MonkeyPatch
) -> None:
    def lose_then_fail(inv: Invitation, token: str) -> None:
        InvitationEmail.objects.filter(invitation=inv).update(claim_id=None)
        raise TimeoutError

    monkeypatch.setattr(invitation_outbox, "_send", lose_then_fail)
    assert invitation_outbox.deliver_due(batch_size=10).as_dict()["lease_lost"] == 1

    def lose_then_cancel(inv: Invitation, now: Any) -> str:
        InvitationEmail.objects.filter(invitation=inv).update(claim_id=None)
        return "not_pending"

    InvitationEmail.objects.filter(invitation=invitation).update(
        next_attempt_at=timezone.now(), claimed_until=None
    )
    monkeypatch.setattr(invitation_outbox, "_undeliverable_reason", lose_then_cancel)
    assert invitation_outbox.deliver_due(batch_size=10).as_dict()["lease_lost"] == 1


def test_command_and_configuration_guards(invitation: Invitation, settings: Any) -> None:
    out = StringIO()
    call_command("deliver_invitation_emails", "--status", stdout=out)
    assert json.loads(out.getvalue())["pending"] == 1
    out = StringIO()
    call_command("deliver_invitation_emails", "--batch-size", "5", stdout=out)
    assert "delivered=1" in out.getvalue()
    assert EMAIL not in out.getvalue()
    with pytest.raises(CommandError):
        call_command("deliver_invitation_emails", "--batch-size", "0")
    with pytest.raises(ValueError, match="batch_size"):
        invitation_outbox.deliver_due(batch_size=0)
    settings.INVITATION_OUTBOX = {**settings.INVITATION_OUTBOX, "lease_seconds": 1}
    with pytest.raises(CommandError, match="lease"):
        call_command("deliver_invitation_emails")


def test_initial_owner_invitation_is_not_sent_once_the_organization_is_active(
    platform_admin: Any,
) -> None:
    from apps.organizations.services import create_organization  # noqa: PLC0415

    organization = create_organization(
        actor=platform_admin,
        name="Pending",
        slug="pending-org",
        organization_type="other",
        initial_owner_email=EMAIL,
    )
    Organization.objects.filter(pk=organization.pk).update(status=OrganizationStatus.ACTIVE)
    assert deliver() == {}
    assert InvitationEmail.objects.get().last_failure == "organization_unavailable"
