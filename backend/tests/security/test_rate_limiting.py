"""Rate limiting and enumeration resistance (plan §4.5, ADR-0004, ADR-0013, ADR-0019).

The atomic PostgreSQL limiter itself (single-statement increments, digests only, purge) is tested
in ``apps/accounts/tests/test_login_and_rate_limits.py``. This suite attacks it: concurrency at
the boundary, header spoofing, window boundaries and every public entry point.
"""

import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from django.db import connections
from django.test import Client, RequestFactory, override_settings

from apps.accounts import ratelimit
from apps.accounts.models import AuthRateLimit
from apps.accounts.tests.conftest import PASSWORD
from apps.core.net import client_ip

LOGIN = "/api/v1/auth/login/"


WRONG_PASSWORD = "wrong-password"  # deliberately wrong test credential


def _login(email: str, password: str = WRONG_PASSWORD, **extra: Any) -> int:
    return (
        Client()
        .post(
            LOGIN, {"email": email, "password": password}, content_type="application/json", **extra
        )
        .status_code
    )


# ------------------------------------------------------------------------------- concurrency
@pytest.mark.django_db(transaction=True)
def test_concurrent_requests_cannot_exceed_the_limit() -> None:
    """20 simultaneous attempts against a limit of 5: exactly 5 are counted as allowed."""
    key = ratelimit.digest("ip", "198.51.100.1")
    barrier = threading.Barrier(20)
    allowed: list[bool] = []

    def worker() -> None:
        barrier.wait(timeout=10)
        try:
            with override_settings(AUTH_RATE_LIMITS={"login_ip": (5, 300)}):
                allowed.append(ratelimit.hit("login_ip", key).allowed)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert sorted(allowed) == [False] * 15 + [True] * 5
    assert AuthRateLimit.objects.get(scope="login_ip", key_digest=key).count == 20


@pytest.mark.django_db(transaction=True)
def test_first_denial_is_flagged_exactly_once_under_concurrency() -> None:
    key = ratelimit.digest("ip", "198.51.100.2")
    barrier = threading.Barrier(12)
    flags: list[bool] = []

    def worker() -> None:
        barrier.wait(timeout=10)
        try:
            with override_settings(AUTH_RATE_LIMITS={"login_ip": (3, 300)}):
                flags.append(ratelimit.hit("login_ip", key).first_denial)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert flags.count(True) == 1


# ------------------------------------------------------------------------------- boundaries
@pytest.mark.django_db
def test_window_boundary_and_expiry() -> None:
    key = ratelimit.digest("ip", "198.51.100.3")
    with override_settings(AUTH_RATE_LIMITS={"login_ip": (2, 300)}):
        start = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        assert ratelimit.hit("login_ip", key, start).allowed
        assert ratelimit.hit("login_ip", key, start + timedelta(seconds=10)).allowed
        third = ratelimit.hit("login_ip", key, start + timedelta(seconds=299))
        assert not third.allowed
        assert third.retry_after == 1
        # A new fixed window starts on the boundary.
        assert ratelimit.hit("login_ip", key, start + timedelta(seconds=300)).allowed
    ratelimit.purge_expired(start + timedelta(days=1))
    assert not AuthRateLimit.objects.filter(key_digest=key).exists()


# ------------------------------------------------------------------------------- client IP
@pytest.mark.parametrize(
    ("trusted", "forwarded", "remote", "expected"),
    [
        (0, "203.0.113.9", "10.0.0.1", "10.0.0.1"),  # untrusted: header ignored
        (1, "203.0.113.9", "10.0.0.1", "203.0.113.9"),
        (1, "1.1.1.1, 203.0.113.9", "10.0.0.1", "203.0.113.9"),  # client-supplied prefix ignored
        (2, "1.1.1.1, 203.0.113.9, 10.0.0.2", "10.0.0.1", "203.0.113.9"),
        (1, "not-an-ip", "10.0.0.1", "10.0.0.1"),  # malformed: fall back to the peer
        (1, "", "10.0.0.1", "10.0.0.1"),
        (2, "203.0.113.9", "10.0.0.1", "10.0.0.1"),  # fewer entries than trusted proxies
        (1, "203.0.113.9 , ", "10.0.0.1", "203.0.113.9"),
        (1, "2001:db8::1", "10.0.0.1", "2001:db8::1"),
        (0, "", "garbage", None),
    ],
)
def test_client_ip_resolution(
    trusted: int, forwarded: str, remote: str, expected: str | None
) -> None:
    request = RequestFactory().get("/", HTTP_X_FORWARDED_FOR=forwarded, REMOTE_ADDR=remote)
    with override_settings(TRUSTED_PROXY_COUNT=trusted):
        assert client_ip(request) == expected


@pytest.mark.django_db
def test_forwarded_header_spoofing_cannot_evade_login_limits(make_user: Any) -> None:
    make_user("target@example.org")
    with override_settings(
        AUTH_RATE_LIMITS={
            "login_ip": (3, 300),
            "login_account": (100, 900),
            "login_ip_account": (100, 900),
        },
        TRUSTED_PROXY_COUNT=0,
    ):
        codes = [
            _login(
                "target@example.org",
                HTTP_X_FORWARDED_FOR=f"203.0.113.{i}",
                HTTP_X_REAL_IP=f"198.51.100.{i}",
            )
            for i in range(5)
        ]
    assert codes == [401, 401, 401, 429, 429]


@pytest.mark.django_db
def test_rotating_ips_cannot_evade_the_account_limit(make_user: Any) -> None:
    make_user("target@example.org")
    with override_settings(
        AUTH_RATE_LIMITS={
            "login_ip": (100, 300),
            "login_account": (3, 900),
            "login_ip_account": (100, 900),
        }
    ):
        codes = [_login("TARGET@example.org ", REMOTE_ADDR=f"203.0.113.{i}") for i in range(5)]
    assert codes == [401, 401, 401, 429, 429]


@pytest.mark.django_db
def test_backoff_applies_to_unknown_accounts_identically(make_user: Any) -> None:
    make_user("known@example.org")
    with override_settings(
        AUTH_RATE_LIMITS={
            "login_ip": (1000, 300),
            "login_account": (1000, 900),
            "login_ip_account": (1000, 900),
        },
        AUTH_LOGIN_BACKOFF={"threshold": 2, "base_seconds": 30, "cap_seconds": 60},
    ):
        known = [_login("known@example.org") for _ in range(4)]
        unknown = [_login("unknown@example.org") for _ in range(4)]
        # Even the correct password is refused while backed off.
        locked = _login("known@example.org", PASSWORD)
    assert known == unknown == [401, 401, 429, 429]
    assert locked == 429


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("scope", "path", "body"),
    [
        ("password_reset_ip", "/api/v1/auth/password/reset/", {"email": "x@example.org"}),
        (
            "password_reset_confirm_ip",
            "/api/v1/auth/password/reset/confirm/",
            {"uid": "x", "token": "y", "new_password": "z" * 14},
        ),
        ("invitation_ip", "/api/v1/invitations/" + "A" * 43 + "/accept/", {}),
    ],
)
def test_every_public_entry_point_is_limited(scope: str, path: str, body: dict[str, Any]) -> None:
    limits = {
        "password_reset_ip": (1000, 3600),
        "password_reset_account": (1000, 3600),
        "password_reset_confirm_ip": (1000, 3600),
        "invitation_ip": (1000, 300),
        scope: (2, 300),
    }
    with override_settings(AUTH_RATE_LIMITS=limits):
        codes = [
            Client().post(path, body, content_type="application/json").status_code for _ in range(3)
        ]
    assert codes[-1] == 429
    response = None
    with override_settings(AUTH_RATE_LIMITS=limits):
        response = Client().post(path, body, content_type="application/json")
    assert int(response["Retry-After"]) >= 1


@pytest.mark.django_db
def test_limiter_stores_no_identifiers(make_user: Any) -> None:
    make_user("private@example.org")
    _login("private@example.org", REMOTE_ADDR="203.0.113.77")
    text = repr(list(AuthRateLimit.objects.values()))
    assert "private@example.org" not in text
    assert "203.0.113.77" not in text
