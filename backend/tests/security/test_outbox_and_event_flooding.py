"""Email outbox and audit-volume attacks (review findings AEMS-024 and AEMS-025, ADR-0019).

AEMS-024: ``max_attempts`` was enforced only when sending raised. A delivery run that stopped after
claiming a row (killed by a scheduler timeout, out of memory, or an exception outside the send)
recorded nothing, so the row was reclaimed after every lease without limit; for invitations each
reclaim rotated the token and sent another email until the invitation expired.

AEMS-025: every refused request (rate limit) and every failed CSRF check on the public cookie
endpoints wrote a durable audit row, so an unauthenticated client could grow the append-only audit
table without bound.
"""

from datetime import timedelta
from typing import Any

import pytest
from django.core import mail
from django.test import Client, override_settings
from django.utils import timezone

from apps.accounts import outbox as reset_outbox
from apps.accounts.models import PasswordResetOutbox, User
from apps.accounts.outbox import FailureCategory, Outcome
from apps.accounts.tests.conftest import PASSWORD
from apps.audit.models import AuditLog
from apps.organizations import invitation_outbox, invitations
from apps.organizations.models import Invitation, InvitationEmail
from apps.rbac.tests.conftest import Team

pytestmark = pytest.mark.django_db
LOGIN = "/api/v1/auth/login/"
REFRESH = "/api/v1/auth/token/refresh/"


def _crash_after_claim(claim: Any, lease: timedelta, times: int) -> Any:
    """Claim the next row ``times`` times without recording any outcome (a killed worker)."""
    moment = timezone.now()
    row = None
    for _ in range(times):
        row = claim(moment, lease=lease)
        assert row is not None
        moment += lease + timedelta(seconds=1)
    return row, moment


# ------------------------------------------------------------------------------- AEMS-024
def test_invitation_rows_abandoned_by_crashed_runs_stop_after_max_attempts(team: Team) -> None:
    invitation = invitations.create_invitation(
        actor=team.owner,
        organization=team.org,
        email="crash@example.org",
        role_ids=[team.auditors.pk],
    )
    config = invitation_outbox.outbox_settings()
    _row, moment = _crash_after_claim(
        invitation_outbox.claim_next, config.lease, config.max_attempts
    )
    sent = len(mail.outbox)
    digest_before = Invitation.objects.get(pk=invitation.pk).token_hash

    report = invitation_outbox.deliver_due(batch_size=10, clock=lambda: moment)

    assert report.claimed == 1
    row = InvitationEmail.objects.get(invitation=invitation)
    assert (row.status, row.last_failure) == ("failed", FailureCategory.ABANDONED)
    assert len(mail.outbox) == sent  # no further email
    assert Invitation.objects.get(pk=invitation.pk).token_hash == digest_before  # no new token
    entry = AuditLog.objects.get(action="invitation.delivery_failed")
    assert entry.metadata["category"] == "abandoned"
    assert entry.metadata["retry_scheduled"] is False
    # Nothing is claimed again.
    later = moment + timedelta(days=1)
    assert invitation_outbox.deliver_due(batch_size=10, clock=lambda: later).claimed == 0


def test_invitation_rows_within_budget_are_still_delivered(team: Team) -> None:
    invitations.create_invitation(
        actor=team.owner,
        organization=team.org,
        email="late@example.org",
        role_ids=[team.auditors.pk],
    )
    config = invitation_outbox.outbox_settings()
    _row, moment = _crash_after_claim(
        invitation_outbox.claim_next, config.lease, config.max_attempts - 1
    )
    report = invitation_outbox.deliver_due(batch_size=10, clock=lambda: moment)
    assert report.outcomes == {"delivered": 1}
    assert mail.outbox[-1].to == ["late@example.org"]


def test_reset_rows_abandoned_by_crashed_runs_stop_after_max_attempts() -> None:
    user = User.objects.create_user("reset@example.org", PASSWORD, full_name="R")
    Client().post(
        "/api/v1/auth/password/reset/", {"email": user.email}, content_type="application/json"
    )
    config = reset_outbox.outbox_settings()
    row, moment = _crash_after_claim(reset_outbox.claim_next, config.lease, config.max_attempts)
    assert row.attempts == config.max_attempts
    claimed = reset_outbox.claim_next(moment, lease=config.lease)
    assert claimed is not None
    assert reset_outbox.deliver_claimed(claimed, clock=lambda: moment, config=config) is (
        Outcome.FAILED
    )
    assert PasswordResetOutbox.objects.get(pk=row.pk).status == "failed"
    assert mail.outbox == []


def test_abandoned_is_a_permanent_category() -> None:
    assert FailureCategory.ABANDONED in reset_outbox.PERMANENT_FAILURES
    assert reset_outbox.attempts_exhausted(6, 5)
    assert not reset_outbox.attempts_exhausted(5, 5)


# ------------------------------------------------------------------------------- AEMS-025
@override_settings(
    AUTH_RATE_LIMITS={
        "login_ip": (2, 300),
        "login_account": (100, 900),
        "login_ip_account": (100, 900),
    }
)
def test_refused_requests_write_one_durable_event_per_window(events: Any) -> None:
    for _ in range(25):
        Client().post(
            LOGIN, {"email": "x@example.org", "password": "wrong"}, content_type="application/json"
        )
    assert AuditLog.objects.filter(action="auth.rate_limited").count() == 1
    assert AuditLog.objects.filter(action="auth.login.failed").count() == 2
    # Every refusal is still observable in the security-event log stream.
    assert [e.name for e in events].count("auth.rate_limited") == 23


@override_settings(AUTH_RATE_LIMITS={"invitation_ip": (3, 300), "csrf_failure_ip": (20, 300)})
def test_invitation_route_floods_are_bounded() -> None:
    for _ in range(30):
        Client().get(f"/api/v1/invitations/{'x' * 43}/")
    assert AuditLog.objects.filter(action="auth.rate_limited").count() == 1


def test_csrf_failures_are_recorded_within_a_budget(events: Any) -> None:
    client = Client(enforce_csrf_checks=True)
    client.cookies["aems_refresh"] = "anything"
    for _ in range(40):
        response = client.post(REFRESH, HTTP_ORIGIN="https://evil.example")
        assert response.status_code == 403
    assert AuditLog.objects.filter(action="auth.csrf.failed").count() == 20
    recorded = AuditLog.objects.filter(action="auth.csrf.failed").first()
    assert recorded is not None
    assert recorded.ip_address == "127.0.0.1"
    assert [e.name for e in events].count("auth.csrf.failed") == 40
