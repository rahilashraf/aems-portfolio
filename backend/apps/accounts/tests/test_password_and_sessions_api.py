"""Password change/reset flows and the session-management API."""

import re
from datetime import timedelta
from typing import Any

import pytest
from django.core import mail
from django.test import Client, override_settings
from django.utils import timezone

from apps.accounts.models import AuthSession, RevokeReason, User
from apps.accounts.tokens import decode_access_token, password_reset_tokens

from .conftest import ME_URL, PASSWORD, REFRESH_COOKIE, SESSIONS_URL, do_login, event_names

pytestmark = pytest.mark.django_db
CHANGE_URL = "/api/v1/auth/password/change/"
RESET_URL = "/api/v1/auth/password/reset/"
CONFIRM_URL = "/api/v1/auth/password/reset/confirm/"
NEW_PASSWORD = "A-Much-Better-Passphrase-77"


def _me(token: str) -> int:
    return Client().get(ME_URL, HTTP_AUTHORIZATION=f"Bearer {token}").status_code


class TestPasswordChange:
    def _change(self, token: str, current: str = PASSWORD, new: str = NEW_PASSWORD) -> Any:
        return Client().post(
            CHANGE_URL,
            {"current_password": current, "new_password": new},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

    def test_change_revokes_all_sessions_and_issues_a_new_one(self, user: User) -> None:
        laptop, phone = do_login(user.email), do_login(user.email)
        before = timezone.now()

        response = self._change(laptop.access_token)

        assert response.status_code == 200
        new_access = response.json()["access_token"]
        assert REFRESH_COOKIE in response.cookies
        user.refresh_from_db()
        assert user.check_password(NEW_PASSWORD)
        assert user.password_changed_at is not None
        assert user.password_changed_at >= before
        assert _me(laptop.access_token) == 401
        assert _me(phone.access_token) == 401
        assert phone.refresh().status_code == 401
        assert _me(new_access) == 200
        reasons = set(
            AuthSession.objects.filter(revoked_at__isnull=False).values_list(
                "revoke_reason", flat=True
            )
        )
        assert reasons == {RevokeReason.PASSWORD_CHANGED}
        assert AuthSession.objects.filter(user=user, revoked_at__isnull=True).count() == 1

    def test_wrong_current_password_is_generic(self, user: User) -> None:
        session = do_login(user.email)
        response = self._change(session.access_token, current="not-my-password")

        assert response.status_code == 400
        [error] = response.json()["errors"]
        assert error["pointer"] == "#/current_password"
        assert error["detail"] == "This value is invalid."
        assert _me(session.access_token) == 200

    @pytest.mark.parametrize(
        "weak", ["short", "12345678901234", "password12345", "x" * 129, "alice@example.org1"]
    )
    def test_weak_new_password_is_rejected(self, user: User, weak: str) -> None:
        session = do_login(user.email)
        response = self._change(session.access_token, new=weak)
        assert response.status_code == 400
        assert response.json()["errors"][0]["pointer"] == "#/new_password"
        assert weak not in response.content.decode()

    def test_requires_authentication(self, db: Any) -> None:
        assert Client().post(CHANGE_URL, {}, content_type="application/json").status_code == 401

    @override_settings(
        AUTH_RATE_LIMITS={
            "password_change_user": (1, 3600),
            "login_ip": (100, 300),
            "login_account": (100, 900),
            "login_ip_account": (100, 900),
        }
    )
    def test_rate_limited(self, user: User) -> None:
        session = do_login(user.email)
        self._change(session.access_token, current="wrong-1")
        assert self._change(session.access_token).status_code == 429


class TestPasswordReset:
    def _request(self, email: str, **extra: Any) -> Any:
        return Client().post(RESET_URL, {"email": email}, content_type="application/json", **extra)

    def _confirm(self, uid: str, token: str, password: str = NEW_PASSWORD) -> Any:
        return Client().post(
            CONFIRM_URL,
            {"uid": uid, "token": token, "new_password": password},
            content_type="application/json",
        )

    def _link_parts(self) -> tuple[str, str]:
        [message] = mail.outbox
        match = re.search(r"/reset-password#uid=([^&\s]+)&token=([^\s]+)", str(message.body))
        assert match, message.body
        return match.group(1), match.group(2)

    def test_existing_and_unknown_accounts_get_identical_responses(self, user: User) -> None:
        known = self._request("  ALICE@example.org ")
        unknown = self._request("nobody@example.org")

        for response in (known, unknown):
            assert response.status_code == 202
        assert known.json() == unknown.json()
        assert len(mail.outbox) == 1
        message = mail.outbox[0]
        assert message.to == ["alice@example.org"]
        assert "#uid=" in message.body  # token in the URL fragment, never a query string
        assert "?token=" not in message.body

    def test_no_email_for_inactive_or_passwordless_accounts(self, make_user: Any) -> None:
        make_user("inactive@example.org", is_active=False)
        make_user("nopass@example.org", password=None)
        assert self._request("inactive@example.org").status_code == 202
        assert self._request("nopass@example.org").status_code == 202
        assert mail.outbox == []

    def test_confirm_sets_password_and_revokes_sessions(
        self, user: User, events: Any, django_capture_on_commit_callbacks: Any
    ) -> None:
        session = do_login(user.email)
        self._request(user.email)
        uid, token = self._link_parts()

        with django_capture_on_commit_callbacks(execute=True):
            response = self._confirm(uid, token)

        assert response.status_code == 204
        user.refresh_from_db()
        assert user.check_password(NEW_PASSWORD)
        assert _me(session.access_token) == 401
        assert AuthSession.objects.get(user=user).revoke_reason == RevokeReason.PASSWORD_RESET
        assert "auth.password_reset.completed" in event_names(events)

    def test_token_is_single_use(self, user: User) -> None:
        self._request(user.email)
        uid, token = self._link_parts()
        assert self._confirm(uid, token).status_code == 204
        second = self._confirm(uid, token, password="Yet-Another-Passphrase-88")
        assert second.status_code == 400
        assert second.json()["code"] == "invalid_reset_token"

    def test_token_invalidated_by_password_change(self, user: User) -> None:
        self._request(user.email)
        uid, token = self._link_parts()
        user.set_password("Changed-Elsewhere-Passphrase-1")
        user.password_changed_at = timezone.now()
        user.save()
        assert self._confirm(uid, token).status_code == 400

    def test_token_expires(self, user: User) -> None:
        self._request(user.email)
        uid, token = self._link_parts()
        with override_settings(PASSWORD_RESET_TIMEOUT=-1):
            assert self._confirm(uid, token).status_code == 400

    @pytest.mark.parametrize(("uid", "token"), [("bad", "bad"), ("MQ", "x-y"), ("", "")])
    def test_invalid_uid_or_token(self, uid: str, token: str, db: Any) -> None:
        response = self._confirm(uid, token)
        assert response.status_code == 400
        assert response.json()["code"] in {"invalid_reset_token", "validation_error"}

    def test_weak_password_rejected_and_token_still_valid(self, user: User) -> None:
        self._request(user.email)
        uid, token = self._link_parts()
        assert self._confirm(uid, token, password="short").status_code == 400
        assert self._confirm(uid, token).status_code == 204

    def test_inactive_user_cannot_complete_reset(self, user: User) -> None:
        self._request(user.email)
        uid, token = self._link_parts()
        User.objects.filter(pk=user.pk).update(is_active=False)
        assert self._confirm(uid, token).status_code == 400

    def test_generator_binds_password_change_time(self, user: User) -> None:
        token = password_reset_tokens.make_token(user)
        user.password_changed_at = timezone.now() + timedelta(seconds=1)
        assert not password_reset_tokens.check_token(user, token)

    @override_settings(
        AUTH_RATE_LIMITS={
            "password_reset_ip": (100, 3600),
            "password_reset_account": (1, 3600),
            "password_reset_confirm_ip": (1, 3600),
        }
    )
    def test_rate_limits_apply_regardless_of_account_existence(self, user: User) -> None:
        assert self._request(user.email).status_code == 202
        assert self._request(user.email).status_code == 429
        assert self._request("ghost@example.org").status_code == 202
        assert self._request("ghost@example.org").status_code == 429
        self._confirm("x", "y")
        assert self._confirm("x", "y").status_code == 429


class TestSessionsApi:
    def test_list_marks_current_session(self, user: User) -> None:
        a = do_login(user.email, client=Client(enforce_csrf_checks=True, HTTP_USER_AGENT="laptop"))
        do_login(user.email, client=Client(enforce_csrf_checks=True, HTTP_USER_AGENT="phone"))
        response = Client().get(SESSIONS_URL, HTTP_AUTHORIZATION=f"Bearer {a.access_token}")

        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2
        assert [s["current"] for s in body["results"]].count(True) == 1
        assert "refresh_jti_hash" not in response.content.decode()

    def test_revoke_one_session(self, user: User) -> None:
        a, b = do_login(user.email), do_login(user.email)
        target = AuthSession.objects.get(id=decode_access_token(b.access_token).session_id)

        response = Client().delete(
            f"{SESSIONS_URL}{target.id}/", HTTP_AUTHORIZATION=f"Bearer {a.access_token}"
        )

        assert response.status_code == 204
        assert _me(b.access_token) == 401
        assert _me(a.access_token) == 200
        again = Client().delete(
            f"{SESSIONS_URL}{target.id}/", HTTP_AUTHORIZATION=f"Bearer {a.access_token}"
        )
        assert again.status_code == 404

    def test_cannot_revoke_another_users_session(self, make_user: Any) -> None:
        alice, bob = make_user(), make_user()
        a, b = do_login(alice.email), do_login(bob.email)
        bob_session = AuthSession.objects.get(user=bob)
        response = Client().delete(
            f"{SESSIONS_URL}{bob_session.id}/", HTTP_AUTHORIZATION=f"Bearer {a.access_token}"
        )
        assert response.status_code == 404
        assert _me(b.access_token) == 200

    def test_revoke_others_keeps_current(self, user: User) -> None:
        sessions = [do_login(user.email) for _ in range(3)]
        response = Client().post(
            f"{SESSIONS_URL}revoke-others/", HTTP_AUTHORIZATION=f"Bearer {sessions[0].access_token}"
        )
        assert response.status_code == 200
        assert response.json() == {"revoked": 2}
        assert [_me(s.access_token) for s in sessions] == [200, 401, 401]

    def test_profile_update(self, user: User) -> None:
        session = do_login(user.email)
        response = Client().patch(
            ME_URL,
            {"full_name": "Alice Updated", "email": "hijack@example.org", "is_staff": True},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {session.access_token}",
        )
        assert response.status_code == 200
        user.refresh_from_db()
        assert user.full_name == "Alice Updated"
        assert user.email == "alice@example.org"  # read-only
        assert user.is_staff is False  # self-escalation is impossible

    def test_profile_rejects_blank_name(self, user: User) -> None:
        session = do_login(user.email)
        response = Client().patch(
            ME_URL,
            {"full_name": ""},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {session.access_token}",
        )
        assert response.status_code == 400
