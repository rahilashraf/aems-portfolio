"""Login, enumeration resistance, atomic rate limiting and account backoff."""

import json
import threading
from datetime import timedelta
from io import StringIO
from typing import Any
from unittest import mock

import pytest
from django.core.management import call_command
from django.db import connections
from django.test import Client, override_settings
from django.utils import timezone

from apps.accounts import ratelimit
from apps.accounts.models import AuthBackoff, AuthRateLimit, AuthSession, User

from .conftest import LOGIN_URL, PASSWORD, REFRESH_COOKIE, event_names

pytestmark = pytest.mark.django_db


def _post_login(
    email: str, password: str = PASSWORD, client: Client | None = None, **extra: Any
) -> Any:
    return (client or Client()).post(
        LOGIN_URL, {"email": email, "password": password}, content_type="application/json", **extra
    )


def _comparable(response: Any) -> tuple[int, dict[str, Any], str | None]:
    body = json.loads(response.content)
    body.pop("request_id", None)
    return response.status_code, body, response.get("WWW-Authenticate")


class TestLoginSuccess:
    def test_returns_access_token_and_sets_refresh_cookie(
        self, user: User, events: Any, django_capture_on_commit_callbacks: Any
    ) -> None:
        with django_capture_on_commit_callbacks(execute=True):
            response = _post_login("  ALICE@example.org ")

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"access_token", "token_type", "expires_in", "user"}
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == 600
        assert body["user"]["email"] == "alice@example.org"
        assert "password" not in json.dumps(body["user"])
        # The refresh token is never in the body.
        cookie = response.cookies[REFRESH_COOKIE]
        assert cookie.value not in response.content.decode()
        assert cookie["httponly"] is True
        assert cookie["secure"] is True
        assert cookie["samesite"] == "Strict"
        assert cookie["path"] == "/api/v1/auth/"
        assert "auth.login.succeeded" in event_names(events)

    def test_creates_server_side_session(self, user: User) -> None:
        _post_login(user.email, HTTP_USER_AGENT="pytest-agent/1.0", REMOTE_ADDR="198.51.100.7")
        session = AuthSession.objects.get(user=user)

        assert session.revoked_at is None
        assert session.created_ip == "198.51.100.7"
        assert session.user_agent == "pytest-agent/1.0"
        assert len(session.refresh_jti_hash) == 64
        user.refresh_from_db()
        assert user.last_login is not None

    def test_forwarded_for_is_ignored_without_trusted_proxy(self, user: User) -> None:
        _post_login(user.email, HTTP_X_FORWARDED_FOR="203.0.113.9", REMOTE_ADDR="198.51.100.7")
        assert AuthSession.objects.get(user=user).created_ip == "198.51.100.7"

    def test_validation_error_for_missing_fields(self, db: Any) -> None:
        response = Client().post(LOGIN_URL, {}, content_type="application/json")
        assert response.status_code == 400
        assert {e["pointer"] for e in response.json()["errors"]} == {"#/email", "#/password"}


class TestEnumerationResistance:
    def test_unknown_wrong_password_and_inactive_are_indistinguishable(
        self, make_user: Any, events: Any
    ) -> None:
        make_user("known@example.org")
        make_user("inactive@example.org", is_active=False)

        responses = [
            _post_login("nobody@example.org"),
            _post_login("known@example.org", "Wrong-Password-123"),
            _post_login("inactive@example.org"),
        ]
        comparable = {json.dumps(_comparable(r), sort_keys=True) for r in responses}

        assert len(comparable) == 1
        status, body, challenge = _comparable(responses[0])
        assert status == 401
        assert body["code"] == "invalid_credentials"
        assert body["detail"] == "Invalid email or password."
        assert challenge == 'Bearer realm="api"'
        assert event_names(events).count("auth.login.failed") == 3

    def test_unknown_account_still_runs_the_password_hasher(self, db: Any) -> None:
        from django.contrib.auth.hashers import MD5PasswordHasher  # noqa: PLC0415

        with mock.patch.object(
            MD5PasswordHasher, "encode", wraps=MD5PasswordHasher().encode
        ) as encode:
            _post_login("nobody@example.org")
        assert encode.call_count >= 1

    def test_failure_events_contain_no_email_or_password(self, events: Any, db: Any) -> None:
        _post_login("secret.person@example.org", "Pw-should-not-leak-1")
        [failed] = [e for e in events if e.name == "auth.login.failed"]
        rendered = repr(failed)
        assert "secret.person" not in rendered
        assert "Pw-should-not-leak-1" not in rendered
        assert failed.subject_digest is not None
        assert len(failed.subject_digest) == 64


SMALL_LIMITS = {
    "login_ip": (3, 300),
    "login_account": (100, 900),
    "login_ip_account": (100, 900),
    "refresh_ip": (100, 300),
    "password_reset_ip": (100, 3600),
    "password_reset_account": (100, 3600),
    "password_reset_confirm_ip": (100, 3600),
    "password_change_user": (100, 3600),
}


class TestRateLimits:
    @override_settings(AUTH_RATE_LIMITS=SMALL_LIMITS)
    def test_login_ip_limit_returns_429_with_retry_after(self, user: User, events: Any) -> None:
        statuses = [_post_login(f"x{i}@example.org").status_code for i in range(3)]
        limited = _post_login(user.email)  # even a correct password is refused once limited

        assert statuses == [401, 401, 401]
        assert limited.status_code == 429
        assert limited.json()["code"] == "throttled"
        assert int(limited["Retry-After"]) >= 1
        assert "auth.rate_limited" in event_names(events)

    @override_settings(
        AUTH_RATE_LIMITS={**SMALL_LIMITS, "login_ip": (100, 300), "login_account": (2, 900)}
    )
    def test_login_account_limit_applies_across_ips(self, user: User) -> None:
        for ip in ("198.51.100.1", "198.51.100.2"):
            _post_login(user.email, "wrong-1", REMOTE_ADDR=ip)
        assert _post_login(user.email, REMOTE_ADDR="198.51.100.3").status_code == 429

    @override_settings(
        AUTH_RATE_LIMITS={**SMALL_LIMITS, "login_ip": (100, 300), "login_ip_account": (1, 900)}
    )
    def test_login_ip_account_limit(self, user: User) -> None:
        _post_login(user.email, "wrong-1")
        assert _post_login(user.email).status_code == 429
        assert _post_login(user.email, REMOTE_ADDR="198.51.100.4").status_code == 200

    def test_limiter_stores_only_digests(self, user: User) -> None:
        _post_login(user.email, "wrong-1", REMOTE_ADDR="198.51.100.77")
        stored = json.dumps(list(AuthRateLimit.objects.values()), default=str)
        stored += json.dumps(list(AuthBackoff.objects.values()), default=str)
        assert user.email not in stored
        assert "198.51.100.77" not in stored

    def test_window_rollover_resets_count(self, db: Any) -> None:
        key = ratelimit.digest("ip", "192.0.2.1")
        now = timezone.now()
        with override_settings(AUTH_RATE_LIMITS={"login_ip": (1, 60)}):
            assert ratelimit.hit("login_ip", key, now).allowed
            assert not ratelimit.hit("login_ip", key, now).allowed
            assert ratelimit.hit("login_ip", key, now + timedelta(seconds=61)).allowed

    def test_digest_is_deterministic_and_namespaced(self) -> None:
        assert ratelimit.digest("ip", "1.2.3.4") == ratelimit.digest("ip", "1.2.3.4")
        assert ratelimit.digest("ip", "1.2.3.4") != ratelimit.digest("email", "1.2.3.4")


@pytest.mark.django_db(transaction=True)
@override_settings(
    AUTH_RATE_LIMITS={"login_ip": (10_000, 300)}
)  # once: settings are process-global
def test_concurrent_increments_are_atomic() -> None:
    """32 threads x 5 hits on one key must count exactly 160 (no lost updates)."""
    key = ratelimit.digest("ip", "203.0.113.50")
    now = timezone.now()
    threads_count, per_thread = 32, 5
    barrier = threading.Barrier(threads_count)
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            barrier.wait(timeout=10)
            for _ in range(per_thread):
                ratelimit.hit("login_ip", key, now)
        except BaseException as exc:
            errors.append(exc)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=worker) for _ in range(threads_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert not errors
    assert (
        AuthRateLimit.objects.get(scope="login_ip", key_digest=key).count
        == threads_count * per_thread
    )


class TestAccountBackoff:
    BACKOFF = {"threshold": 3, "base_seconds": 30, "cap_seconds": 120}

    def test_exponential_and_capped(self, db: Any) -> None:
        key = ratelimit.digest("email", "victim@example.org")
        with override_settings(AUTH_LOGIN_BACKOFF=self.BACKOFF):
            locks = [ratelimit.register_failure(key) for _ in range(7)]
        assert locks == [0, 0, 30, 60, 120, 120, 120]

    @override_settings(AUTH_LOGIN_BACKOFF=BACKOFF)
    def test_locks_even_correct_password_then_expires(self, user: User, events: Any) -> None:
        for _ in range(3):
            assert _post_login(user.email, "wrong-pass-1").status_code == 401
        locked = _post_login(user.email)
        assert locked.status_code == 429
        assert 1 <= int(locked["Retry-After"]) <= 30
        assert "auth.login.locked" in event_names(events)

        AuthBackoff.objects.update(locked_until=timezone.now() - timedelta(seconds=1))
        assert _post_login(user.email).status_code == 200
        assert not AuthBackoff.objects.exists()  # success resets the counter

    @override_settings(AUTH_LOGIN_BACKOFF=BACKOFF)
    def test_unknown_accounts_are_locked_the_same_way(self, db: Any) -> None:
        for _ in range(3):
            _post_login("ghost@example.org", "x-wrong-1")
        assert _post_login("ghost@example.org").status_code == 429


def test_purge_command_removes_expired_records(db: Any) -> None:
    past = timezone.now() - timedelta(days=2)
    AuthRateLimit.objects.create(
        scope="login_ip", key_digest="a" * 64, window_start=past, count=1, expires_at=past
    )
    AuthRateLimit.objects.create(
        scope="login_ip",
        key_digest="b" * 64,
        window_start=timezone.now(),
        count=1,
        expires_at=timezone.now() + timedelta(hours=1),
    )
    AuthBackoff.objects.create(key_digest="c" * 64, failures=9, expires_at=past)
    out = StringIO()

    call_command("purge_auth_rate_limits", stdout=out)

    assert "Deleted 1 rate-limit counter(s) and 1 backoff record(s)." in out.getvalue()
    assert AuthRateLimit.objects.count() == 1
    assert not AuthBackoff.objects.exists()


def test_literal_sql_table_names_match_models() -> None:
    assert AuthRateLimit._meta.db_table == ratelimit.RATE_LIMIT_TABLE
    assert AuthBackoff._meta.db_table == ratelimit.BACKOFF_TABLE
