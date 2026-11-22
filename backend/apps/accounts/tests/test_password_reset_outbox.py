"""Password-reset email outbox: enumeration resistance, delivery, concurrency (ADR-0014)."""

import json
import re
import smtplib
import socket
import threading
import time
from collections.abc import Callable
from datetime import datetime, timedelta
from io import StringIO
from typing import Any

import pytest
from django.contrib import admin
from django.contrib.auth.hashers import UNUSABLE_PASSWORD_PREFIX, make_password
from django.core import mail
from django.core.management import CommandError, call_command
from django.db import DatabaseError, connection, connections, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import Client, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from apps.accounts import outbox
from apps.accounts.models import AuthSession, PasswordResetOutbox, User
from apps.accounts.models import PasswordResetDeliveryStatus as Status
from apps.accounts.outbox import (
    FailureCategory,
    Outcome,
    categorize,
    claim_next,
    deliver_claimed,
    deliver_due,
    outbox_settings,
    purge_finished,
)
from apps.accounts.tokens import password_reset_tokens

from . import failing_mail
from .conftest import PASSWORD, event_names
from .smtp_server import smtp_server

RESET_URL = "/api/v1/auth/password/reset/"
CONFIRM_URL = "/api/v1/auth/password/reset/confirm/"
NEW_PASSWORD = "A-Much-Better-Passphrase-77"
LINK = re.compile(r"/reset-password#uid=(?P<uid>[^&\s]+)&token=(?P<token>[^\s]+)")
FORBIDDEN_BACKEND = "apps.accounts.tests.failing_mail.ForbiddenBackend"
HIGH_LIMITS = {"password_reset_ip": (10_000, 3600), "password_reset_account": (10_000, 3600)}
# Headers that legitimately differ between any two requests.
PER_REQUEST_HEADERS = {"x-request-id"}


def _request(email: str) -> Any:
    return Client().post(RESET_URL, {"email": email}, content_type="application/json")


def _confirm(uid: str, token: str, password: str = NEW_PASSWORD) -> Any:
    return Client().post(
        CONFIRM_URL,
        {"uid": uid, "token": token, "new_password": password},
        content_type="application/json",
    )


def _headers(response: Any) -> dict[str, str]:
    return {k.lower(): v for k, v in response.items() if k.lower() not in PER_REQUEST_HEADERS}


def _links(bodies: list[str]) -> list[tuple[str, str]]:
    found = [LINK.search(body) for body in bodies]
    assert all(found)
    return [(m.group("uid"), m.group("token")) for m in found if m]


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
    return port


def _clock(start: datetime) -> tuple[Callable[[], datetime], Callable[[timedelta], None]]:
    """A controllable clock: (now, advance)."""
    state = {"now": start}

    def advance(delta: timedelta) -> None:
        state["now"] += delta

    return (lambda: state["now"]), advance


def _pending(user: User) -> PasswordResetOutbox:
    return PasswordResetOutbox.objects.get(user=user, status=Status.PENDING)


def _normalized(sql: str) -> str:
    """Strip literals and per-transaction savepoint names, keeping the statement shape."""
    sql = re.sub(r'"s\d+_x\d+"', "SAVEPOINT_NAME", sql)
    return re.sub(r"'(?:[^']|'')*'|\b\d+\b", "?", sql)


# ===================================================================== request path (enqueue)
@pytest.mark.django_db
class TestEnumerationResistance:
    @override_settings(EMAIL_BACKEND=FORBIDDEN_BACKEND)
    def test_identical_responses_and_no_mail_in_the_request(self, user: User) -> None:
        failing_mail.ForbiddenBackend.instances = 0
        known = _request("  ALICE@example.org ")
        unknown = _request("nobody@example.org")

        assert known.status_code == unknown.status_code == 202
        assert known.content == unknown.content
        assert _headers(known) == _headers(unknown)
        assert failing_mail.ForbiddenBackend.instances == 0  # no mail backend was even created
        assert mail.outbox == []
        assert PasswordResetOutbox.objects.count() == 1
        assert _pending(user).attempts == 0

    def test_slow_smtp_server_is_never_contacted_by_the_request(self, user: User) -> None:
        with (
            smtp_server(greeting_delay=3.0) as (email_settings, log),
            override_settings(**email_settings),
        ):
            started = time.perf_counter()
            known = _request(user.email)
            unknown = _request("nobody@example.org")
            elapsed = time.perf_counter() - started

        assert known.status_code == unknown.status_code == 202
        assert known.content == unknown.content
        assert log.connections == 0
        # Relative bound: far below one stalled SMTP greeting, so SMTP cannot be on the path.
        assert elapsed < 3.0

    def test_unavailable_smtp_server_does_not_change_the_response(
        self, user: User, events: Any
    ) -> None:
        with override_settings(
            EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend",
            EMAIL_HOST="127.0.0.1",
            EMAIL_PORT=_closed_port(),
        ):
            known = _request(user.email)
            unknown = _request("nobody@example.org")
        assert known.status_code == unknown.status_code == 202
        assert known.content == unknown.content
        assert _headers(known) == _headers(unknown)
        assert event_names(events) == ["auth.password_reset.requested"] * 2

    @pytest.mark.parametrize("pending_already", [False, True])
    def test_known_and_unknown_addresses_run_the_same_queries(
        self, user: User, pending_already: bool
    ) -> None:
        if pending_already:
            _request(user.email)
        with CaptureQueriesContext(connection) as known:
            _request(user.email)
        with CaptureQueriesContext(connection) as unknown:
            _request("nobody@example.org")

        known_sql = [_normalized(q["sql"]) for q in known.captured_queries]
        unknown_sql = [_normalized(q["sql"]) for q in unknown.captured_queries]
        assert known_sql == unknown_sql
        assert sum("accounts_passwordresetoutbox" in q for q in known_sql) == 1

    def test_no_rows_for_unknown_inactive_or_passwordless_accounts(self, make_user: Any) -> None:
        make_user("inactive@example.org", is_active=False)
        make_user("nopass@example.org", password=None)
        for email in ("nobody@example.org", "inactive@example.org", "nopass@example.org"):
            assert _request(email).status_code == 202
        assert PasswordResetOutbox.objects.count() == 0

    @override_settings(AUTH_RATE_LIMITS=HIGH_LIMITS)
    def test_repeated_requests_cannot_grow_the_queue(self, user: User) -> None:
        for _ in range(25):
            assert _request(user.email).status_code == 202
            assert _request("nobody@example.org").status_code == 202
            assert _request(f"random-{_}@example.org").status_code == 202
        assert PasswordResetOutbox.objects.count() == 1
        row = _pending(user)
        assert row.expires_at - row.requested_at == outbox_settings().ttl

    @override_settings(
        AUTH_RATE_LIMITS={"password_reset_ip": (100, 3600), "password_reset_account": (1, 3600)}
    )
    def test_rate_limits_apply_to_both_and_limited_requests_enqueue_nothing(
        self, user: User
    ) -> None:
        assert _request(user.email).status_code == 202
        assert _request(user.email).status_code == 429
        assert _request("ghost@example.org").status_code == 202
        assert _request("ghost@example.org").status_code == 429
        assert PasswordResetOutbox.objects.count() == 1

    def test_enqueue_database_error_keeps_the_generic_response(
        self, user: User, events: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        baseline = _request("nobody@example.org")

        def broken(*_args: Any, **_kwargs: Any) -> None:
            raise DatabaseError("disk full while writing alice@example.org")

        monkeypatch.setattr("apps.accounts.services.enqueue_password_reset", broken)
        response = _request(user.email)

        assert response.status_code == 202
        assert response.content == baseline.content
        assert _headers(response) == _headers(baseline)
        [failure] = [e for e in events if e.name == "auth.password_reset.enqueue_failed"]
        assert failure.metadata == {"error_type": "DatabaseError"}
        assert user.email not in repr(failure)

    def test_request_event_is_sanitized(self, user: User, events: Any) -> None:
        _request(user.email)
        _request("nobody@example.org")
        known, unknown = events
        assert known.metadata == {"queued": True}
        assert known.user_id == str(user.pk)
        assert unknown.metadata == {"queued": False}
        assert unknown.user_id is None
        assert known.subject_digest != unknown.subject_digest
        for event in events:
            assert "@" not in repr(event)

    def test_literal_sql_table_names_match_models(self) -> None:
        assert PasswordResetOutbox._meta.db_table == outbox.OUTBOX_TABLE
        assert User._meta.db_table == outbox.USER_TABLE
        assert f"INSERT INTO {outbox.OUTBOX_TABLE}" in outbox._ENQUEUE_SQL
        assert f"FROM {outbox.USER_TABLE} " in outbox._ENQUEUE_SQL

    def test_outbox_is_not_exposed(self) -> None:
        assert PasswordResetOutbox not in admin.site._registry
        schema = (
            Client().get("/api/schema/", HTTP_ACCEPT="application/vnd.oai.openapi").content.decode()
        )
        assert "outbox" not in schema.lower()


# ==================================================================================== delivery
@pytest.mark.django_db
class TestDelivery:
    def test_delivers_over_smtp_and_the_link_resets_the_password(self, user: User) -> None:
        _request(user.email)
        with smtp_server() as (email_settings, log), override_settings(**email_settings):
            report = deliver_due(batch_size=10)
            again = deliver_due(batch_size=10)

        assert report.as_dict()["delivered"] == 1
        assert again.claimed == 0  # delivered once, not resent
        [message] = log.messages
        assert message["To"] == user.email
        body = message.get_payload(decode=True).decode()  # type: ignore[union-attr]
        [(uid, token)] = _links([body])
        row = PasswordResetOutbox.objects.get(user=user)
        assert row.status == Status.DELIVERED
        assert row.delivered_at is not None
        assert row.attempts == 1
        assert _confirm(uid, token).status_code == 204
        assert _confirm(uid, token, "Another-Passphrase-99").status_code == 400  # single use

    def test_connection_failure_schedules_a_retry(self, user: User, events: Any) -> None:
        _request(user.email)
        now, _advance = _clock(timezone.now())
        with override_settings(
            EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend",
            EMAIL_HOST="127.0.0.1",
            EMAIL_PORT=_closed_port(),
        ):
            report = deliver_due(batch_size=10, clock=now)

        assert report.as_dict()["retry_scheduled"] == 1
        row = _pending(user)
        assert row.last_failure == FailureCategory.CONNECTION
        assert row.next_attempt_at == now() + timedelta(seconds=60)
        [failure] = [e for e in events if e.name == "auth.password_reset.delivery_failed"]
        assert failure.metadata["category"] == "connection"
        assert failure.metadata["retry_scheduled"] is True

    def test_recipient_rejection_fails_permanently(self, user: User) -> None:
        _request(user.email)
        with (
            smtp_server(reject_recipients=True) as (email_settings, log),
            override_settings(**email_settings),
        ):
            report = deliver_due(batch_size=10)
        assert report.as_dict()["failed"] == 1
        row = PasswordResetOutbox.objects.get(user=user)
        assert row.status == Status.FAILED
        assert row.last_failure == FailureCategory.RECIPIENT_REFUSED
        assert row.attempts == 1
        assert log.messages == []

    def test_timeout_is_categorized_and_retried(self, user: User) -> None:
        _request(user.email)
        with (
            smtp_server(greeting_delay=1.5) as (email_settings, _log),
            override_settings(EMAIL_TIMEOUT=0.3, **email_settings),
        ):
            report = deliver_due(batch_size=10)
        assert report.as_dict()["retry_scheduled"] == 1
        assert _pending(user).last_failure == FailureCategory.TIMEOUT

    @override_settings(
        EMAIL_BACKEND="apps.accounts.tests.failing_mail.ConnectionRefusedBackend",
        PASSWORD_RESET_OUTBOX={
            "ttl_seconds": 7200,
            "max_attempts": 4,
            "backoff_base_seconds": 60,
            "backoff_cap_seconds": 150,
            "lease_seconds": 120,
            "retention_seconds": 3600,
            "max_batch_size": 1000,
        },
    )
    def test_retry_backoff_is_bounded_by_max_attempts(self, user: User) -> None:
        _request(user.email)
        now, advance = _clock(timezone.now())
        delays = []
        for attempt in range(1, 5):
            report = deliver_due(batch_size=10, clock=now)
            assert report.claimed == 1
            row = PasswordResetOutbox.objects.get(user=user)
            assert row.attempts == attempt
            if row.status == Status.FAILED:
                break
            delay = row.next_attempt_at - now()
            delays.append(delay)
            advance(delay - timedelta(seconds=1))
            assert deliver_due(batch_size=10, clock=now).claimed == 0  # not due yet
            advance(timedelta(seconds=1))

        assert delays == [timedelta(seconds=s) for s in (60, 120, 150)]  # doubling, capped
        row = PasswordResetOutbox.objects.get(user=user)
        assert row.status == Status.FAILED
        assert row.attempts == 4
        advance(timedelta(days=1))
        assert deliver_due(batch_size=10, clock=now).claimed == 0

    def test_expired_work_is_never_sent(self, user: User, events: Any) -> None:
        _request(user.email)
        now, advance = _clock(timezone.now())
        advance(outbox_settings().ttl + timedelta(seconds=1))
        report = deliver_due(batch_size=10, clock=now)

        assert report.expired == 1
        assert report.claimed == 0
        assert mail.outbox == []
        assert PasswordResetOutbox.objects.get(user=user).status == Status.EXPIRED
        assert "auth.password_reset.delivery_expired" in event_names(events)

    def test_request_superseded_by_a_password_change_is_cancelled(self, user: User) -> None:
        _request(user.email)
        user.set_password("Changed-Elsewhere-Passphrase-1")
        user.password_changed_at = timezone.now() + timedelta(seconds=1)
        user.save()

        report = deliver_due(batch_size=10)

        assert report.as_dict()["cancelled"] == 1
        assert mail.outbox == []
        row = PasswordResetOutbox.objects.get(user=user)
        assert (row.status, row.last_failure) == (Status.CANCELLED, "superseded")

    @pytest.mark.parametrize("change", [{"is_active": False}, {"password": "!unusable"}])
    def test_ineligible_account_is_cancelled(self, user: User, change: dict[str, Any]) -> None:
        _request(user.email)
        User.objects.filter(pk=user.pk).update(**change)
        deliver_due(batch_size=10)
        assert mail.outbox == []
        row = PasswordResetOutbox.objects.get(user=user)
        assert (row.status, row.last_failure) == (Status.CANCELLED, "account_ineligible")

    def test_email_goes_to_the_current_address(self, user: User) -> None:
        _request(user.email)
        User.objects.filter(pk=user.pk).update(email="alice.new@example.org")
        deliver_due(batch_size=10)
        [message] = mail.outbox
        assert message.to == ["alice.new@example.org"]

    def test_crashed_worker_lease_expires_and_work_is_recovered(
        self, user: User, events: Any
    ) -> None:
        _request(user.email)
        config = outbox_settings()
        now, advance = _clock(timezone.now())
        crashed = claim_next(now(), lease=config.lease)  # claimed, then the process "dies"
        assert crashed is not None

        advance(config.lease - timedelta(seconds=1))
        assert claim_next(now(), lease=config.lease) is None  # lease still held
        advance(timedelta(seconds=2))
        recovered = claim_next(now(), lease=config.lease)
        assert recovered is not None
        assert recovered.attempts == 2
        assert recovered.claim_id != crashed.claim_id

        # The original worker waking up cannot overwrite the new claimant's outcome.
        assert deliver_claimed(crashed, clock=now, config=config) == Outcome.LEASE_LOST
        assert "auth.password_reset.delivery_lease_lost" in event_names(events)
        assert deliver_claimed(recovered, clock=now, config=config) == Outcome.DELIVERED
        assert PasswordResetOutbox.objects.get(user=user).status == Status.DELIVERED
        # At-least-once: the stale worker had already sent before losing the lease.
        assert len(mail.outbox) == 2

    def test_duplicate_after_crash_is_bounded_and_tokens_stay_single_use(
        self, user: User, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _request(user.email)
        now, advance = _clock(timezone.now())
        real_finish = outbox._finish

        def crash_after_smtp(*_args: Any, **_kwargs: Any) -> bool:
            raise SystemExit("worker killed between SMTP acceptance and the status update")

        monkeypatch.setattr(outbox, "_finish", crash_after_smtp)
        with pytest.raises(SystemExit):
            deliver_due(batch_size=10, clock=now)
        monkeypatch.setattr(outbox, "_finish", real_finish)
        assert len(mail.outbox) == 1
        assert _pending(user).attempts == 1

        advance(outbox_settings().lease + timedelta(seconds=1))
        assert deliver_due(batch_size=10, clock=now).as_dict()["delivered"] == 1

        assert len(mail.outbox) == 2  # the documented duplicate
        row = PasswordResetOutbox.objects.get(user=user)
        assert row.status == Status.DELIVERED
        assert row.attempts == 2 <= outbox_settings().max_attempts
        (uid1, token1), (uid2, token2) = _links([str(m.body) for m in mail.outbox])
        assert _confirm(uid2, token2).status_code == 204
        assert _confirm(uid1, token1, "Another-Passphrase-99").status_code == 400

    def test_rows_hold_no_address_token_or_body(self, user: User) -> None:
        _request(user.email)
        deliver_due(batch_size=10)
        [(uid, token)] = _links([str(mail.outbox[0].body)])
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM {outbox.OUTBOX_TABLE}")  # noqa: S608 - constant
            raw = repr(cursor.fetchall())
        for secret in (user.email, token, uid, "reset-password"):
            assert secret not in raw
        columns = {f.name for f in PasswordResetOutbox._meta.get_fields()}
        assert not columns & {"email", "recipient", "token", "body", "payload", "link"}

    def test_finished_rows_are_purged_after_retention(self, make_user: Any) -> None:
        now = timezone.now()
        retention = outbox_settings().retention
        old = now - retention - timedelta(minutes=1)
        recent = now - timedelta(minutes=1)

        def row(status: str, completed: datetime | None) -> PasswordResetOutbox:
            return PasswordResetOutbox.objects.create(
                user=make_user(),
                requested_at=old,
                expires_at=old,
                next_attempt_at=old,
                status=status,
                completed_at=completed,
            )

        purged = [row(s, old) for s in (Status.DELIVERED, Status.FAILED, Status.EXPIRED)]
        kept = [row(Status.DELIVERED, recent), row(Status.PENDING, None)]

        assert purge_finished(now, retention=retention) == len(purged)
        assert set(PasswordResetOutbox.objects.values_list("pk", flat=True)) == {r.pk for r in kept}

    def test_logs_and_events_never_contain_the_address_or_token(
        self, user: User, events: Any, caplog: pytest.LogCaptureFixture
    ) -> None:
        _request(user.email)
        with override_settings(
            EMAIL_BACKEND="apps.accounts.tests.failing_mail.RecipientsRefusedBackend"
        ):
            deliver_due(batch_size=10)  # failure path: the exception names the recipient
        _request(user.email)
        deliver_due(batch_size=10)
        [(uid, token)] = _links([str(mail.outbox[0].body)])

        rendered = caplog.text + "".join(repr(e) for e in events)
        assert "auth.password_reset.delivery_failed" in rendered
        assert "auth.password_reset.email_delivered" in rendered
        for secret in (user.email, token, f"uid={uid}", "mailbox unavailable"):
            assert secret not in rendered


@pytest.mark.parametrize(
    ("exc", "category"),
    [
        (smtplib.SMTPRecipientsRefused({}), FailureCategory.RECIPIENT_REFUSED),
        (smtplib.SMTPAuthenticationError(535, b"no"), "smtp_authentication"),
        (smtplib.SMTPServerDisconnected("gone"), FailureCategory.CONNECTION),
        (ConnectionRefusedError(), FailureCategory.CONNECTION),
        (TimeoutError(), FailureCategory.TIMEOUT),
        (smtplib.SMTPDataError(554, b"no"), FailureCategory.SMTP_ERROR),
        (OSError("dns"), FailureCategory.NETWORK),
        (RuntimeError("bug"), FailureCategory.UNEXPECTED),
    ],
)
def test_failure_categories(exc: BaseException, category: str) -> None:
    assert categorize(exc) == category


def test_timeout_chained_by_smtplib_is_a_timeout() -> None:
    def disconnected_by_timeout() -> None:
        try:
            raise TimeoutError("timed out")
        except TimeoutError as inner:
            raise smtplib.SMTPServerDisconnected("Connection unexpectedly closed") from inner

    with pytest.raises(smtplib.SMTPServerDisconnected) as excinfo:
        disconnected_by_timeout()
    assert categorize(excinfo.value) == FailureCategory.TIMEOUT


# ================================================================================ concurrency
@pytest.mark.django_db(transaction=True)
def test_skip_locked_prevents_concurrent_claims(make_user: Any) -> None:
    user = make_user()
    _request(user.email)
    lease = outbox_settings().lease
    locked, release = threading.Event(), threading.Event()

    def hold_row_lock() -> None:
        try:
            with transaction.atomic():
                PasswordResetOutbox.objects.select_for_update().get(user=user)
                locked.set()
                release.wait(timeout=10)
        finally:
            connections.close_all()

    holder = threading.Thread(target=hold_row_lock)
    holder.start()
    assert locked.wait(timeout=10)
    try:
        assert claim_next(timezone.now(), lease=lease) is None  # skipped, not waited for
    finally:
        release.set()
        holder.join(timeout=10)
    assert claim_next(timezone.now(), lease=lease) is not None


@pytest.mark.django_db(transaction=True)
@override_settings(AUTH_RATE_LIMITS=HIGH_LIMITS)
def test_concurrent_runs_deliver_each_message_exactly_once(make_user: Any) -> None:
    users = [make_user() for _ in range(12)]
    for user in users:
        assert _request(user.email).status_code == 202
    workers = 4
    barrier = threading.Barrier(workers)
    errors: list[BaseException] = []

    def run() -> None:
        try:
            barrier.wait(timeout=10)
            deliver_due(batch_size=len(users))
        except BaseException as exc:
            errors.append(exc)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=run) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert errors == []
    recipients = sorted(m.to[0] for m in mail.outbox)
    assert recipients == sorted(u.email for u in users)  # each exactly once
    rows = PasswordResetOutbox.objects.all()
    assert {r.status for r in rows} == {Status.DELIVERED}
    assert {r.attempts for r in rows} == {1}


# ==================================================================================== command
@pytest.mark.django_db
class TestCommand:
    def test_delivers_and_prints_counts_only(self, user: User) -> None:
        _request(user.email)
        out = StringIO()
        call_command("deliver_password_reset_emails", "--batch-size", "5", stdout=out)
        output = out.getvalue()
        assert "claimed=1" in output
        assert "delivered=1" in output
        assert user.email not in output
        assert len(mail.outbox) == 1

    def test_status_reports_counts_without_identifiers(self, user: User) -> None:
        _request(user.email)
        out = StringIO()
        call_command("deliver_password_reset_emails", "--status", stdout=out)
        status = json.loads(out.getvalue())
        assert status["pending"] == 1
        assert status["pending_due"] == 1
        assert status["delivered"] == 0
        assert str(user.pk) not in out.getvalue()
        assert user.email not in out.getvalue()
        assert mail.outbox == []  # --status never sends

    @pytest.mark.parametrize("size", ["0", "1001", "-3"])
    def test_rejects_out_of_range_batch_sizes(self, size: str) -> None:
        with pytest.raises(CommandError, match="batch-size"):
            call_command("deliver_password_reset_emails", "--batch-size", size)

    @override_settings(EMAIL_TIMEOUT=600)
    def test_refuses_a_lease_shorter_than_the_smtp_timeout(self) -> None:
        with pytest.raises(CommandError, match="lease_seconds must exceed EMAIL_TIMEOUT"):
            call_command("deliver_password_reset_emails")


def test_password_constant_is_still_used_for_logins() -> None:
    """Guard: the outbox SQL relies on Django's unusable-password prefix."""
    assert make_password(None).startswith(UNUSABLE_PASSWORD_PREFIX)
    assert not make_password(PASSWORD).startswith(UNUSABLE_PASSWORD_PREFIX)
    assert password_reset_tokens.key_salt == "aems.accounts.password-reset"


# ================================================================================= migrations
@pytest.mark.django_db(transaction=True)
def test_outbox_migration_preserves_existing_users_and_sessions() -> None:
    """Upgrade path: a database at accounts.0001 with data migrates to 0002 unchanged."""
    before = [("accounts", "0001_initial")]
    executor = MigrationExecutor(connection)
    executor.migrate(before)
    old_apps = executor.loader.project_state(before).apps
    old_user = old_apps.get_model("accounts", "User")
    old_session = old_apps.get_model("accounts", "AuthSession")
    now = timezone.now()
    user = old_user.objects.create(
        email="legacy@example.org",
        full_name="Legacy",
        password="argon2$argon2id$placeholder-hash",
        password_changed_at=now,
    )
    session = old_session.objects.create(
        user=user, refresh_jti_hash="a" * 64, expires_at=now + timedelta(days=1)
    )
    snapshot = (
        list(old_user.objects.values()),
        list(old_session.objects.values()),
    )
    assert "accounts_passwordresetoutbox" not in connection.introspection.table_names()

    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate(executor.loader.graph.leaf_nodes())

    assert "accounts_passwordresetoutbox" in connection.introspection.table_names()
    assert (
        list(User.objects.values()),
        list(AuthSession.objects.values()),
    ) == snapshot
    assert PasswordResetOutbox.objects.count() == 0
    assert session.pk is not None


@pytest.mark.django_db
class TestLeaseEdgeCases:
    def _stolen(self, user: User) -> tuple[PasswordResetOutbox, Callable[[], datetime]]:
        """A claim whose lease expired and was taken over by another run."""
        _request(user.email)
        config = outbox_settings()
        now, advance = _clock(timezone.now())
        stale = claim_next(now(), lease=config.lease)
        advance(config.lease + timedelta(seconds=1))
        assert claim_next(now(), lease=config.lease) is not None
        assert stale is not None
        return stale, now

    @override_settings(EMAIL_BACKEND="apps.accounts.tests.failing_mail.TimeoutBackend")
    def test_stale_worker_cannot_record_a_failure(self, user: User) -> None:
        stale, now = self._stolen(user)
        outcome = deliver_claimed(stale, clock=now, config=outbox_settings())
        assert outcome == Outcome.LEASE_LOST
        assert _pending(user).last_failure == ""

    def test_stale_worker_cannot_cancel(self, user: User) -> None:
        stale, now = self._stolen(user)
        User.objects.filter(pk=user.pk).update(is_active=False)
        assert deliver_claimed(stale, clock=now, config=outbox_settings()) == Outcome.LEASE_LOST
        assert _pending(user).status == Status.PENDING

    def test_row_expiring_after_its_claim_is_not_sent(self, user: User) -> None:
        _request(user.email)
        config = outbox_settings()
        now, advance = _clock(timezone.now())
        row = claim_next(now(), lease=config.lease)
        assert row is not None
        advance(config.ttl)
        assert deliver_claimed(row, clock=now, config=config) == Outcome.EXPIRED
        assert mail.outbox == []

    @pytest.mark.parametrize("size", [0, 1001])
    def test_batch_size_is_bounded(self, size: int) -> None:
        with pytest.raises(ValueError, match="batch_size"):
            deliver_due(batch_size=size)
