"""Review corrections: AEMS-015 (profile changes are audited), AEMS-016 (logout failure policy)."""

from typing import Any

import pytest
from django.db import DatabaseError, transaction
from django.test import Client

from apps.accounts.models import AuthSession, RevokeReason, User
from apps.accounts.services import update_profile
from apps.accounts.tests.conftest import (
    LOGOUT_URL,
    ME_URL,
    PASSWORD,
    REFRESH_COOKIE,
    do_login,
)
from apps.audit.models import AuditLog
from apps.core import security_events

from .conftest import all_rows_text, rows

pytestmark = pytest.mark.django_db

#: A value a client tries to smuggle into a profile update; it must never be stored anywhere.
PLANTED = "Leaked-Password-99"


def _fail_audit_inserts(monkeypatch: pytest.MonkeyPatch) -> None:
    def failing_save(*_args: Any, **_kwargs: Any) -> None:
        raise DatabaseError("audit storage unavailable")

    monkeypatch.setattr(AuditLog, "save", failing_save)


def _patch_me(session: Any, body: dict[str, Any], client: Client | None = None) -> Any:
    return (client or Client()).patch(ME_URL, body, content_type="application/json", **session.auth)


# ------------------------------------------------------------------------------ AEMS-015
class TestProfileUpdateAudit:
    def test_change_is_recorded_with_the_user_as_actor_and_target(self, user: User) -> None:
        session = do_login(user.email)
        response = _patch_me(session, {"full_name": "Alice Updated"})
        assert response.status_code == 200
        assert response.json()["full_name"] == "Alice Updated"
        [row] = rows(action="auth.account.profile_updated")
        assert (row.actor_id, row.actor_email) == (user.pk, user.email)
        assert (row.target_type, row.target_id) == ("user", str(user.pk))
        assert row.outcome == "success"
        assert row.changes == {"full_name": {"from": user.full_name, "to": "Alice Updated"}}
        assert row.metadata == {}

    def test_response_contract_is_unchanged(self, user: User) -> None:
        session = do_login(user.email)
        auth: dict[str, Any] = session.auth
        before = Client().get(ME_URL, **auth).json()
        after = _patch_me(session, {"full_name": "Alice Updated"}).json()
        assert set(after) == set(before)
        assert after == {**before, "full_name": "Alice Updated"}

    def test_unchanged_submission_records_nothing(self, user: User) -> None:
        session = do_login(user.email)
        response = _patch_me(session, {"full_name": user.full_name})
        assert response.status_code == 200
        assert response.json()["full_name"] == user.full_name
        assert _patch_me(session, {}).status_code == 200  # empty partial update
        assert rows(action="auth.account.profile_updated") == []

    def test_only_allowlisted_fields_are_applied_or_recorded(self, user: User) -> None:
        session = do_login(user.email)
        body = {
            "full_name": "Alice Updated",
            "email": "hijack@example.org",
            "is_staff": True,
            "password": PLANTED,
        }
        assert _patch_me(session, body).status_code == 200
        user.refresh_from_db()
        assert (user.email, user.is_staff) == ("alice@example.org", False)
        assert user.check_password(PASSWORD)
        [row] = rows(action="auth.account.profile_updated")
        assert set(row.changes) == {"full_name"}
        text = all_rows_text()
        for secret in (PLANTED, PASSWORD, session.access_token, "hijack@"):
            assert secret not in text

    def test_service_refuses_fields_outside_the_profile(self, user: User) -> None:
        with pytest.raises(ValueError, match="is_staff"):
            update_profile(user, {"is_staff": True})
        user.refresh_from_db()
        assert user.is_staff is False

    def test_audit_failure_rolls_back_the_profile_change(
        self, user: User, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = do_login(user.email)
        _fail_audit_inserts(monkeypatch)
        with pytest.raises(DatabaseError, match="audit storage"):
            update_profile(user, {"full_name": "Never Saved"})
        response = _patch_me(
            session, {"full_name": "Never Saved"}, Client(raise_request_exception=False)
        )
        assert response.status_code == 500  # no success for a change that was not committed
        user.refresh_from_db()
        assert user.full_name != "Never Saved"
        assert not AuditLog.objects.filter(action="auth.account.profile_updated").exists()

    def test_profile_rollback_discards_the_audit_event(self, user: User) -> None:
        original = user.full_name

        def update_then_fail() -> None:
            with transaction.atomic():
                update_profile(user, {"full_name": "Rolled Back"})
                raise RuntimeError("later step failed")

        with pytest.raises(RuntimeError):
            update_then_fail()
        user.refresh_from_db()
        assert user.full_name == original
        assert rows(action="auth.account.profile_updated") == []

    def test_blank_name_is_rejected_without_an_event(self, user: User) -> None:
        session = do_login(user.email)
        assert _patch_me(session, {"full_name": ""}).status_code == 400
        assert rows(action="auth.account.profile_updated") == []


# ------------------------------------------------------------------------------ AEMS-016
class TestLogoutFailurePolicy:
    def test_revocation_has_exactly_one_durable_record(
        self, user: User, events: list[security_events.SecurityEvent]
    ) -> None:
        session = do_login(user.email)
        response = session.client.post(LOGOUT_URL, **session.csrf_headers())
        assert response.status_code == 204
        auth_session = AuthSession.objects.get(user=user)
        assert auth_session.revoked_at is not None
        [revoked] = rows(action="auth.session.revoked")
        assert revoked.metadata == {
            "session_id": str(auth_session.pk),
            "reason": RevokeReason.LOGOUT,
        }
        assert rows(action="auth.logout") == []  # observational only, never durable
        [logged] = [e for e in events if e.name == "auth.logout"]
        assert logged.session_id == str(auth_session.pk)
        assert logged.user_id == str(user.pk)
        assert logged.metadata == {"revoked": True}

    def test_revocation_audit_failure_rolls_back_and_is_not_a_success(
        self, user: User, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = do_login(user.email)
        session.client.raise_request_exception = False
        headers = session.csrf_headers()
        _fail_audit_inserts(monkeypatch)
        response = session.client.post(LOGOUT_URL, **headers)
        assert response.status_code == 500
        assert REFRESH_COOKIE not in response.cookies  # the cookie is not cleared on failure
        assert AuthSession.objects.get(user=user).revoked_at is None  # nothing committed
        assert not AuditLog.objects.filter(action="auth.session.revoked").exists()
        monkeypatch.undo()
        # The client can retry: the same session is then revoked and recorded once.
        assert session.client.post(LOGOUT_URL, **headers).status_code == 204
        assert AuthSession.objects.get(user=user).revoked_at is not None
        assert len(rows(action="auth.session.revoked")) == 1

    def test_no_audit_insert_after_the_committed_revocation(
        self, user: User, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Former 500-after-commit: revocation committed, then a second audit insert failed."""
        session = do_login(user.email)
        session.client.raise_request_exception = False
        headers = session.csrf_headers()
        original = AuditLog.save
        inserts: list[str] = []

        def first_insert_only(entry: AuditLog, *args: Any, **kwargs: Any) -> None:
            inserts.append(entry.action)
            if len(inserts) > 1:
                raise DatabaseError("audit storage unavailable")
            original(entry, *args, **kwargs)

        monkeypatch.setattr(AuditLog, "save", first_insert_only)
        response = session.client.post(LOGOUT_URL, **headers)
        assert inserts == ["auth.session.revoked"]
        assert response.status_code == 204
        assert response.cookies[REFRESH_COOKIE].value == ""
        assert AuthSession.objects.get(user=user).revoked_at is not None

    def test_bearer_logout_audit_failure_rolls_back(
        self, user: User, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = do_login(user.email)
        _fail_audit_inserts(monkeypatch)
        auth: dict[str, Any] = session.auth
        response = Client(raise_request_exception=False).post(LOGOUT_URL, **auth)
        assert response.status_code == 500
        assert AuthSession.objects.get(user=user).revoked_at is None

    def test_nothing_after_the_committed_revocation_can_fail_the_response(self, user: User) -> None:
        def broken(_event: Any) -> None:
            raise RuntimeError("log pipeline down")

        session = do_login(user.email)
        headers = session.csrf_headers()
        unregister = security_events.register_sink(broken)
        try:
            response = session.client.post(LOGOUT_URL, **headers)
        finally:
            unregister()
        assert response.status_code == 204
        assert response.cookies[REFRESH_COOKIE].value == ""
        assert AuthSession.objects.get(user=user).revoked_at is not None
        assert len(rows(action="auth.session.revoked")) == 1

    @pytest.mark.parametrize("cookie", [None, "garbage"])
    def test_logout_without_a_usable_session_is_204_and_writes_no_revocation(
        self, cookie: str | None
    ) -> None:
        client = Client()
        if cookie is not None:
            client.cookies[REFRESH_COOKIE] = cookie
        response = client.post(LOGOUT_URL)
        assert response.status_code == 204
        assert rows(action="auth.session.revoked") == []
        assert rows(action="auth.logout") == []

    def test_repeated_logout_records_one_revocation(self, user: User) -> None:
        session = do_login(user.email)
        headers = session.csrf_headers()
        token = session.refresh_token
        assert session.client.post(LOGOUT_URL, **headers).status_code == 204
        session.client.cookies[REFRESH_COOKIE] = token
        assert session.client.post(LOGOUT_URL, **headers).status_code == 204
        assert len(rows(action="auth.session.revoked")) == 1

    def test_csrf_is_still_enforced_when_a_refresh_cookie_is_sent(self, user: User) -> None:
        session = do_login(user.email)
        response = session.client.post(LOGOUT_URL)  # cookie, but no CSRF token
        assert response.status_code == 403
        assert AuthSession.objects.get(user=user).revoked_at is None
        assert rows(action="auth.session.revoked") == []
        assert len(rows(action="auth.csrf.failed")) == 1
