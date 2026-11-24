"""Atomic refresh rotation, replay detection, concurrency and CSRF (ADR-0004)."""

import threading
from datetime import timedelta
from typing import Any

import pytest
from django.db import connections
from django.test import Client
from django.utils import timezone

from apps.accounts.models import AuthSession, RevokeReason, User
from apps.accounts.sessions import (
    RotationOutcome,
    create_session,
    rotate,
    session_for_refresh_token,
)
from apps.accounts.tokens import issue_refresh_token
from apps.audit.models import AuditLog

from .conftest import (
    CSRF_URL,
    LOGOUT_URL,
    ME_URL,
    REFRESH_COOKIE,
    REFRESH_URL,
    Session,
    do_login,
    event_names,
)


def _me(access_token: str) -> int:
    return Client().get(ME_URL, HTTP_AUTHORIZATION=f"Bearer {access_token}").status_code


# --------------------------------------------------------------------------- rotation
@pytest.mark.django_db
class TestRotation:
    def test_refresh_rotates_cookie_and_returns_new_access_token(
        self, user: User, login: Any
    ) -> None:
        session = login(user.email)
        old_refresh = session.refresh_token

        response = session.refresh()

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"access_token", "token_type", "expires_in"}
        new_refresh = response.cookies[REFRESH_COOKIE].value
        assert new_refresh != old_refresh
        assert new_refresh not in response.content.decode()
        assert response.cookies[REFRESH_COOKIE]["httponly"] is True
        assert _me(body["access_token"]) == 200
        stored = AuthSession.objects.get(user=user)
        assert stored.revoked_at is None

    def test_missing_or_garbage_cookie_is_generic_401_and_clears_cookie(self, db: Any) -> None:
        client = Client(enforce_csrf_checks=True)
        session = Session(client=client, access_token="")
        response = session.refresh()
        assert response.status_code == 401
        assert response.json()["code"] == "authentication_failed"
        assert response.cookies[REFRESH_COOKIE].value == ""

        client.cookies[REFRESH_COOKIE] = "garbage"
        assert session.refresh().status_code == 401

    def test_expired_session_cannot_refresh(self, user: User, login: Any) -> None:
        session = login(user.email)
        AuthSession.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        assert session.refresh().status_code == 401

    def test_inactive_user_cannot_refresh(self, user: User, login: Any) -> None:
        session = login(user.email)
        User.objects.filter(pk=user.pk).update(is_active=False)
        assert session.refresh().status_code == 401

    def test_service_rejects_garbage(self, db: Any) -> None:
        assert rotate("not-a-token").outcome is RotationOutcome.INVALID


@pytest.mark.django_db(transaction=True)
class TestReplayDetection:
    """transaction=True: verify real commits, i.e. the revocation survives the 401 response."""

    def test_replayed_refresh_token_revokes_the_whole_family(self, user: User, events: Any) -> None:
        session = do_login(user.email)
        stolen = session.refresh_token
        rotated = session.refresh()
        assert rotated.status_code == 200
        new_access = rotated.json()["access_token"]

        # Attacker replays the old (already rotated) refresh token.
        attacker = Client(enforce_csrf_checks=True)
        attacker.cookies[REFRESH_COOKIE] = stolen
        replay = Session(client=attacker, access_token="").refresh()

        assert replay.status_code == 401
        assert replay.json()["code"] == "authentication_failed"  # generic, no "reuse" hint
        # The revocation committed although the response was an error.
        stored = AuthSession.objects.get(user=user)
        assert stored.revoked_at is not None
        assert stored.revoke_reason == RevokeReason.REFRESH_REUSE
        assert "auth.refresh.reuse_detected" in event_names(events)
        # Every token of the family is dead: the legitimate holder's refresh and access tokens too.
        assert session.refresh().status_code == 401
        assert _me(new_access) == 401
        assert _me(session.access_token) == 401

    def test_older_tokens_can_never_be_reused(self, user: User) -> None:
        issued = create_session(user, client_ip=None)
        first = issued.refresh_token
        second = rotate(first)
        assert second.outcome is RotationOutcome.ROTATED
        assert rotate(first).outcome is RotationOutcome.REUSE_DETECTED
        assert second.tokens is not None
        assert rotate(second.tokens.refresh_token).outcome is RotationOutcome.INVALID  # revoked


@pytest.mark.django_db(transaction=True)
def test_concurrent_refresh_with_the_same_token_lets_exactly_one_win(
    user: User, events: Any
) -> None:
    """Row locking serialises rotation: one request rotates, the rest are treated as replay."""
    issued = create_session(user, client_ip=None)
    workers = 8
    barrier = threading.Barrier(workers)
    outcomes: list[RotationOutcome | BaseException] = []

    def worker() -> None:
        try:
            barrier.wait(timeout=10)
            outcomes.append(rotate(issued.refresh_token).outcome)
        except BaseException as exc:
            outcomes.append(exc)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert outcomes.count(RotationOutcome.ROTATED) == 1
    assert all(
        o in (RotationOutcome.ROTATED, RotationOutcome.REUSE_DETECTED, RotationOutcome.INVALID)
        for o in outcomes
    )
    assert RotationOutcome.REUSE_DETECTED in outcomes
    session = AuthSession.objects.get(pk=issued.session.pk)
    assert session.revoked_at is not None
    assert session.revoke_reason == RevokeReason.REFRESH_REUSE
    assert _me(issued.access_token) == 401


@pytest.mark.django_db(transaction=True)
def test_concurrent_refresh_over_http(user: User) -> None:
    session = do_login(user.email)
    headers = session.csrf_headers()
    cookies = {name: morsel.value for name, morsel in session.client.cookies.items()}
    workers = 6
    barrier = threading.Barrier(workers)
    statuses: list[int] = []

    def worker() -> None:
        client = Client(enforce_csrf_checks=True)
        for name, value in cookies.items():
            client.cookies[name] = value
        try:
            barrier.wait(timeout=10)
            statuses.append(client.post(REFRESH_URL, **headers).status_code)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert sorted(statuses) == [200] + [401] * (workers - 1)
    assert AuthSession.objects.get(user=user).revoke_reason == RevokeReason.REFRESH_REUSE


# --------------------------------------------------------------------------- CSRF
@pytest.mark.django_db
class TestCsrf:
    def test_csrf_bootstrap_sets_readable_strict_cookie(self) -> None:
        response = Client().get(CSRF_URL)
        assert response.status_code == 200
        cookie = response.cookies["csrftoken"]
        assert cookie["httponly"] == ""  # readable by the SPA (double-submit)
        assert cookie["samesite"] == "Strict"

    def test_missing_csrf_token(self, user: User, login: Any) -> None:
        session = login(user.email)
        response = session.client.post(REFRESH_URL, HTTP_ORIGIN="http://testserver")
        assert response.status_code == 403
        assert response.json()["code"] == "csrf_failed"
        assert AuthSession.objects.get(user=user).revoked_at is None  # nothing happened

    def test_invalid_csrf_token(self, user: User, login: Any) -> None:
        session = login(user.email)
        session.client.get(CSRF_URL)
        response = session.client.post(
            REFRESH_URL, HTTP_X_CSRFTOKEN="x" * 64, HTTP_ORIGIN="http://testserver"
        )
        assert response.status_code == 403
        assert response.json()["code"] == "csrf_failed"

    def test_foreign_origin(self, user: User, login: Any) -> None:
        session = login(user.email)
        headers: dict[str, Any] = {**session.csrf_headers(), "HTTP_ORIGIN": "https://evil.example"}
        response = session.client.post(REFRESH_URL, **headers)
        assert response.status_code == 403
        assert response.json()["code"] == "csrf_failed"

    def test_https_requires_matching_referer_without_origin(self, user: User, login: Any) -> None:
        session = login(user.email)
        token = session.csrf_headers()["HTTP_X_CSRFTOKEN"]
        bad = session.client.post(
            REFRESH_URL, secure=True, HTTP_X_CSRFTOKEN=token, HTTP_REFERER="https://evil.example/x"
        )
        assert bad.status_code == 403
        good = session.client.post(
            REFRESH_URL, secure=True, HTTP_X_CSRFTOKEN=token, HTTP_REFERER="https://testserver/app"
        )
        assert good.status_code == 200

    def test_valid_same_origin_request(self, user: User, login: Any) -> None:
        session = login(user.email)
        assert session.refresh().status_code == 200

    def test_logout_with_cookie_requires_csrf(self, user: User, login: Any) -> None:
        session = login(user.email)
        response = session.client.post(LOGOUT_URL, HTTP_ORIGIN="http://testserver")
        assert response.status_code == 403
        assert AuthSession.objects.get(user=user).revoked_at is None

    def test_logout_revokes_and_refresh_fails_afterwards(self, user: User, login: Any) -> None:
        session = login(user.email)
        old_refresh = session.refresh_token
        response = session.client.post(LOGOUT_URL, **session.csrf_headers())

        assert response.status_code == 204
        assert response.cookies[REFRESH_COOKIE].value == ""
        stored = AuthSession.objects.get(user=user)
        assert stored.revoke_reason == RevokeReason.LOGOUT
        assert _me(session.access_token) == 401
        session.client.cookies[REFRESH_COOKIE] = old_refresh
        assert session.refresh().status_code == 401

    def test_bearer_only_logout_needs_no_csrf(self, user: User, login: Any) -> None:
        session = login(user.email)
        response = Client().post(LOGOUT_URL, HTTP_AUTHORIZATION=f"Bearer {session.access_token}")
        assert response.status_code == 204
        assert AuthSession.objects.get(user=user).revoked_at is not None

    def test_logout_is_idempotent_and_tolerates_bad_tokens(self, db: Any) -> None:
        client = Client(enforce_csrf_checks=True)
        assert client.post(LOGOUT_URL).status_code == 204
        assert client.post(LOGOUT_URL, HTTP_AUTHORIZATION="Bearer nope").status_code == 204
        client.get(CSRF_URL)
        client.cookies[REFRESH_COOKIE] = "garbage"
        headers: dict[str, Any] = {
            "HTTP_X_CSRFTOKEN": client.cookies["csrftoken"].value,
            "HTTP_ORIGIN": "http://testserver",
        }
        assert client.post(LOGOUT_URL, **headers).status_code == 204


# --------------------------------------------------------------------------- logout binding
def _forged_refresh(*, user_id: Any, session_id: Any, now: Any = None) -> str:
    """A refresh token signed with the real key (as after a key leak or a defect)."""
    token, _jti = issue_refresh_token(
        user_id=str(user_id),
        session_id=str(session_id),
        session_expires_at=timezone.now() + timedelta(days=30),
        now=now,
    )
    return token


def _cookie_logout(client: Client, refresh_token: str, **extra: Any) -> Any:
    client.cookies[REFRESH_COOKIE] = refresh_token
    if "csrftoken" not in client.cookies:
        client.get(CSRF_URL)
    return client.post(
        LOGOUT_URL,
        HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value,
        HTTP_ORIGIN="http://testserver",
        **extra,
    )


@pytest.mark.django_db
class TestLogoutTokenBinding:
    """AEMS-011: logout revokes only the session that the token's ``sid`` *and* ``sub`` name."""

    def test_mismatched_user_and_session_claims_revoke_nothing(
        self, make_user: Any, events: Any
    ) -> None:
        alice = make_user("alice@example.org")
        bob = make_user("bob@example.org")
        do_login(bob.email)
        bobs_session = AuthSession.objects.get(user=bob)
        forged = _forged_refresh(user_id=alice.pk, session_id=bobs_session.pk)

        response = _cookie_logout(Client(enforce_csrf_checks=True), forged)

        assert response.status_code == 204
        assert response.cookies[REFRESH_COOKIE].value == ""
        bobs_session.refresh_from_db()
        assert bobs_session.revoked_at is None
        [mismatch] = [e for e in events if e.name == "auth.session.owner_mismatch"]
        assert mismatch.outcome == "failure"
        assert mismatch.session_id == str(bobs_session.pk)
        assert mismatch.metadata["token_user_id"] == str(alice.pk)
        row = AuditLog.objects.get(action="auth.session.owner_mismatch")
        assert (row.target_type, row.target_id) == ("session", str(bobs_session.pk))
        assert row.metadata["token_user_id"] == str(alice.pk)
        [logout] = [e for e in events if e.name == "auth.logout"]
        assert logout.session_id is None
        assert logout.metadata["revoked"] is False
        assert not AuditLog.objects.filter(action="auth.logout").exists()  # log only

    def test_mismatched_cookie_does_not_block_the_callers_bearer_logout(
        self, make_user: Any
    ) -> None:
        alice = make_user("alice@example.org")
        bob = make_user("bob@example.org")
        alice_session = do_login(alice.email)
        do_login(bob.email)
        bobs_session = AuthSession.objects.get(user=bob)
        forged = _forged_refresh(user_id=alice.pk, session_id=bobs_session.pk)

        response = _cookie_logout(alice_session.client, forged, **alice_session.auth)

        assert response.status_code == 204
        assert AuthSession.objects.get(user=alice).revoked_at is not None
        assert AuthSession.objects.get(user=bob).revoked_at is None

    def test_unknown_session_is_a_no_op_204(self, user: User, events: Any) -> None:
        do_login(user.email)
        forged = _forged_refresh(user_id=user.pk, session_id="00000000-0000-4000-8000-000000000000")

        response = _cookie_logout(Client(enforce_csrf_checks=True), forged)

        assert response.status_code == 204
        assert response.cookies[REFRESH_COOKIE].value == ""
        assert AuthSession.objects.get(user=user).revoked_at is None
        assert "auth.session.owner_mismatch" not in event_names(events)

    def test_already_revoked_session_is_idempotent(self, user: User, login: Any) -> None:
        session = login(user.email)
        stored = AuthSession.objects.get(user=user)
        revoked_at = timezone.now() - timedelta(minutes=5)
        AuthSession.objects.filter(pk=stored.pk).update(
            revoked_at=revoked_at, revoke_reason=RevokeReason.USER_REVOKED
        )

        for _ in range(2):
            response = session.client.post(LOGOUT_URL, **session.csrf_headers())
            assert response.status_code == 204
            assert response.cookies[REFRESH_COOKIE].value == ""

        stored.refresh_from_db()
        assert stored.revoked_at == revoked_at  # the original revocation is not overwritten
        assert stored.revoke_reason == RevokeReason.USER_REVOKED

    def test_expired_refresh_token_clears_cookie_without_revoking(
        self, user: User, login: Any
    ) -> None:
        login(user.email)
        stored = AuthSession.objects.get(user=user)
        expired = _forged_refresh(
            user_id=user.pk, session_id=stored.pk, now=timezone.now() - timedelta(days=8)
        )

        response = _cookie_logout(Client(enforce_csrf_checks=True), expired)

        assert response.status_code == 204
        assert response.cookies[REFRESH_COOKIE].value == ""
        stored.refresh_from_db()
        assert stored.revoked_at is None  # an expired token is no proof of possession

    def test_invalid_cookie_still_requires_csrf(self, user: User, login: Any) -> None:
        session = login(user.email)
        client = Client(enforce_csrf_checks=True)
        client.cookies[REFRESH_COOKIE] = "garbage"
        response = client.post(LOGOUT_URL, HTTP_ORIGIN="http://testserver", **session.auth)
        assert response.status_code == 403
        assert response.json()["code"] == "csrf_failed"
        assert AuthSession.objects.get(user=user).revoked_at is None

    def test_invalid_cookie_with_valid_bearer_revokes_only_the_bearer_session(
        self, user: User, login: Any
    ) -> None:
        first = login(user.email)
        second = login(user.email)
        response = _cookie_logout(Client(enforce_csrf_checks=True), "garbage", **first.auth)

        assert response.status_code == 204
        assert response.cookies[REFRESH_COOKIE].value == ""
        assert _me(first.access_token) == 401
        assert _me(second.access_token) == 200

    def test_bearer_only_logout_revokes_the_bearer_session(self, user: User, login: Any) -> None:
        first = login(user.email)
        second = login(user.email)
        response = Client().post(LOGOUT_URL, **first.auth)

        assert response.status_code == 204
        assert response.cookies[REFRESH_COOKIE].value == ""
        assert _me(first.access_token) == 401
        assert _me(second.access_token) == 200
        assert Client().post(LOGOUT_URL, **first.auth).status_code == 204  # idempotent

    def test_session_lookup_requires_both_claims(self, make_user: Any) -> None:
        alice = make_user("alice@example.org")
        bob = make_user("bob@example.org")
        tokens = create_session(bob, client_ip=None)
        bobs_session = AuthSession.objects.get(user=bob)

        assert session_for_refresh_token(tokens.refresh_token) == bobs_session
        forged = _forged_refresh(user_id=alice.pk, session_id=bobs_session.pk)
        assert session_for_refresh_token(forged) is None
        assert session_for_refresh_token("garbage") is None
