"""Password-reset attacks (plan §4.4, §8, ADR-0013, ADR-0014, ADR-0019).

The per-feature behaviour (outbox delivery, retries, leases, purge) is tested in
``apps/accounts/tests/test_password_reset_outbox.py``; this suite attacks the flow end to end.
"""

import re
import threading
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from django.core import mail
from django.db import connections
from django.test import Client, override_settings
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from apps.accounts.models import AuthSession, PasswordResetOutbox, User
from apps.accounts.outbox import deliver_due
from apps.accounts.tests.conftest import PASSWORD, do_login
from apps.accounts.tokens import password_reset_tokens
from apps.audit.models import AuditLog

pytestmark = pytest.mark.django_db
RESET = "/api/v1/auth/password/reset/"
CONFIRM = "/api/v1/auth/password/reset/confirm/"
NEW_PASSWORD = "Brand-New-Passphrase-For-Reset-58"
LINK = re.compile(r"#uid=(?P<uid>[^&\s]+)&token=(?P<token>[^\s]+)")
VARYING_HEADERS = {"x-request-id"}


@pytest.fixture
def account(make_user: Callable[..., User]) -> User:
    return make_user("reset-target@example.org")


def _request(email: Any) -> Any:
    return Client().post(RESET, {"email": email}, content_type="application/json")


def _confirm(uid: str, token: str, password: str = NEW_PASSWORD) -> Any:
    return Client().post(
        CONFIRM,
        {"uid": uid, "token": token, "new_password": password},
        content_type="application/json",
    )


def _link_for(user: User) -> tuple[str, str]:
    fresh = User.objects.get(pk=user.pk)
    return urlsafe_base64_encode(force_bytes(fresh.pk)), password_reset_tokens.make_token(fresh)


def _shape(response: Any) -> tuple[int, bytes, tuple[tuple[str, str], ...], frozenset[str]]:
    headers = sorted(
        (k.lower(), v) for k, v in response.headers.items() if k.lower() not in VARYING_HEADERS
    )
    return response.status_code, response.content, tuple(headers), frozenset(response.cookies)


# ------------------------------------------------------------------------------- enumeration
def test_existing_unknown_inactive_and_malformed_addresses_answer_identically(
    account: User, make_user: Callable[..., User]
) -> None:
    inactive = make_user("inactive-target@example.org")
    User.objects.filter(pk=inactive.pk).update(is_active=False)
    answers = {
        _shape(_request(email))
        for email in (
            account.email,
            "  RESET-TARGET@Example.ORG ",  # normalized to the existing account
            "nobody@example.org",
            inactive.email,
            "not-an-email",  # any string is accepted: validation must not reveal anything
        )
    }
    assert len(answers) == 1
    (status, _body, _headers, cookies) = answers.pop()
    assert status == 202
    assert cookies == set()


def test_requests_never_send_mail_in_the_request(account: User) -> None:
    """Delivery happens later in the outbox worker: SMTP latency cannot reveal existence."""
    _request(account.email)
    _request("nobody@example.org")
    assert mail.outbox == []
    assert PasswordResetOutbox.objects.count() == 1  # only the real account is queued


def test_normalized_variants_queue_at_most_one_email(account: User) -> None:
    with override_settings(
        AUTH_RATE_LIMITS={"password_reset_ip": (100, 3600), "password_reset_account": (100, 3600)}
    ):
        for variant in (
            "reset-target@example.org",
            "RESET-TARGET@EXAMPLE.ORG",
            " reset-target@example.org",
        ):
            assert _request(variant).status_code == 202
    assert PasswordResetOutbox.objects.filter(user=account).count() == 1


@pytest.mark.parametrize("email", ["", ["a@example.org"], {"$gt": ""}, None, "a" * 300])
def test_invalid_input_is_a_generic_validation_error(email: Any) -> None:
    response = _request(email)
    assert response.status_code == 400
    assert "a" * 300 not in response.content.decode()


def test_rate_limits_apply_equally_to_unknown_accounts(account: User) -> None:
    with override_settings(
        AUTH_RATE_LIMITS={"password_reset_ip": (100, 3600), "password_reset_account": (2, 3600)}
    ):
        known = [_request(account.email).status_code for _ in range(3)]
        unknown = [_request("ghost@example.org").status_code for _ in range(3)]
    assert known == unknown == [202, 202, 429]


# ------------------------------------------------------------------------------- tokens
def test_token_is_single_use(account: User) -> None:
    uid, token = _link_for(account)
    assert _confirm(uid, token).status_code == 204
    assert _confirm(uid, token, "Yet-Another-Passphrase-61").status_code == 400
    assert User.objects.get(pk=account.pk).check_password(NEW_PASSWORD)


def test_token_expires(account: User) -> None:
    from unittest import mock  # noqa: PLC0415

    uid, token = _link_for(account)
    later = timezone.now() + timedelta(hours=2)
    with mock.patch.object(password_reset_tokens, "_now", return_value=later.replace(tzinfo=None)):
        assert _confirm(uid, token).status_code == 400
    assert User.objects.get(pk=account.pk).check_password(PASSWORD)


@pytest.mark.parametrize(
    "tamper",
    [
        lambda uid, token: (uid, token[:-1] + ("a" if token[-1] != "a" else "b")),
        lambda uid, token: (uid, token.split("-")[0] + "-" + "0" * 32),
        lambda uid, token: (urlsafe_base64_encode(b"00000000-0000-0000-0000-000000000000"), token),
        lambda uid, token: ("%%%", token),
        lambda uid, token: (uid, ""),
        lambda uid, token: (uid, "x" * 500),
    ],
)
def test_tampered_tokens_are_rejected(
    account: User, tamper: Callable[[str, str], tuple[str, str]]
) -> None:
    uid, token = tamper(*_link_for(account))
    response = _confirm(uid, token)
    assert response.status_code == 400
    assert User.objects.get(pk=account.pk).check_password(PASSWORD)


def test_token_for_one_user_does_not_work_for_another(account: User, make_user: Any) -> None:
    other = make_user("other-target@example.org")
    _uid, token = _link_for(account)
    other_uid, _ = _link_for(other)
    assert _confirm(other_uid, token).status_code == 400


def test_weak_passwords_are_rejected_and_the_token_survives(account: User) -> None:
    uid, token = _link_for(account)
    for weak in ("short", "password1234", "123456789012", "reset-target@example.org"):
        assert _confirm(uid, token, weak).status_code == 400
    assert _confirm(uid, token).status_code == 204


def test_reset_revokes_sessions_and_old_passwords(account: User) -> None:
    session = do_login(account.email)
    uid, token = _link_for(account)
    assert _confirm(uid, token).status_code == 204
    assert not AuthSession.objects.filter(user=account, revoked_at__isnull=True).exists()
    assert session.refresh().status_code == 401
    login = Client().post(
        "/api/v1/auth/login/",
        {"email": account.email, "password": PASSWORD},
        content_type="application/json",
    )
    assert login.status_code == 401


@pytest.mark.django_db(transaction=True)
def test_concurrent_consumption_of_one_token_succeeds_once(account: User) -> None:
    uid, token = _link_for(account)
    passwords = [f"Concurrent-Passphrase-{i}-Xq" for i in range(4)]
    barrier = threading.Barrier(len(passwords))
    codes: list[int] = []

    def worker(password: str) -> None:
        barrier.wait(timeout=10)
        try:
            codes.append(_confirm(uid, token, password).status_code)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=worker, args=(p,)) for p in passwords]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert sorted(codes) == [204, 400, 400, 400]
    fresh = User.objects.get(pk=account.pk)
    assert sum(fresh.check_password(p) for p in passwords) == 1
    assert AuditLog.objects.filter(action="auth.password_reset.completed").count() == 1


# ------------------------------------------------------------------------------- secrets
def test_reset_tokens_never_reach_audit_rows_logs_or_responses(
    account: User, json_logs: Any
) -> None:
    _request(account.email)
    deliver_due(batch_size=10)
    [message] = mail.outbox
    match = LINK.search(str(message.body))
    assert match is not None
    uid, token = match["uid"], match["token"]
    response = _confirm(uid, token)
    assert response.status_code == 204
    audit_text = repr(list(AuditLog.objects.values()))
    for secret in (token, NEW_PASSWORD):
        assert secret not in audit_text
        assert secret not in json_logs.text
        assert secret not in response.content.decode()
    outbox_text = repr(list(PasswordResetOutbox.objects.values()))
    assert token not in outbox_text
    assert account.email not in outbox_text
