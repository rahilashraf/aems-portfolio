"""Which events each authentication, session, admin and organization operation records."""

import re
from typing import Any

import pytest
from django.contrib.auth.models import Permission
from django.core import mail
from django.db import connection
from django.test import Client

from apps.accounts.models import AuthSession, RevokeReason, User
from apps.accounts.outbox import deliver_due
from apps.accounts.sessions import rotate
from apps.accounts.tests.conftest import (
    LOGIN_URL,
    LOGOUT_URL,
    PASSWORD,
    REFRESH_COOKIE,
    SESSIONS_URL,
    do_login,
)
from apps.audit.models import AuditLog

from .conftest import all_rows_text, rows

NEW_PASSWORD = "A-Much-Better-Passphrase-77"


def _actions() -> list[str]:
    with connection.cursor() as cursor:
        cursor.execute("SELECT action FROM audit_auditlog ORDER BY created_at, id")
        return [row[0] for row in cursor.fetchall()]


@pytest.mark.django_db
class TestAuthenticationEvents:
    def test_successful_login(self, user: User) -> None:
        do_login(user.email)
        [row] = rows(action="auth.login.succeeded")
        session = AuthSession.objects.get(user=user)
        assert (row.actor_id, row.actor_email) == (user.pk, user.email)
        assert (row.target_type, row.target_id) == ("session", str(session.pk))
        assert row.metadata == {"session_id": str(session.pk)}
        assert row.organization_id is None

    def test_rate_limit_rejection(self, user: User, settings: Any) -> None:
        settings.AUTH_RATE_LIMITS = {**settings.AUTH_RATE_LIMITS, "login_ip": (1, 300)}
        do_login(user.email)
        response = Client().post(
            LOGIN_URL, {"email": user.email, "password": PASSWORD}, content_type="application/json"
        )
        assert response.status_code == 429
        [row] = rows(action="auth.rate_limited")
        assert (row.outcome, row.metadata["scope"]) == ("failure", "login")

    def test_rejected_refresh_and_rotation_policy(self, user: User) -> None:
        session = do_login(user.email)
        assert session.refresh().status_code == 200  # rotation: operational log only
        assert rows(action="auth.refresh.rotated") == []
        session.client.cookies[REFRESH_COOKIE] = "garbage"
        assert session.refresh().status_code == 401
        [rejected] = rows(action="auth.refresh.rejected")
        assert rejected.metadata == {"reason": "invalid_token"}

    def test_logout_records_the_revocation_only(self, user: User) -> None:
        session = do_login(user.email)
        assert session.client.post(LOGOUT_URL, **session.csrf_headers()).status_code == 204
        [revoked] = rows(action="auth.session.revoked")
        assert revoked.metadata["reason"] == RevokeReason.LOGOUT
        assert revoked.actor_id == user.pk
        assert rows(action="auth.logout") == []  # AEMS-016: observational log only

    def test_session_revocation_endpoints(self, user: User) -> None:
        first, second, third = (do_login(user.email) for _ in range(3))
        target = AuthSession.objects.filter(user=user).order_by("created_at")[1]
        headers: dict[str, Any] = first.auth
        Client().delete(f"{SESSIONS_URL}{target.pk}/", **headers)
        Client().post(f"{SESSIONS_URL}revoke-others/", **headers)
        [single] = rows(action="auth.session.revoked")
        [bulk] = rows(action="auth.sessions.revoked")
        assert single.target_id == str(target.pk)
        assert bulk.metadata == {"reason": RevokeReason.OTHER_SESSIONS_REVOKED, "count": 1}
        assert bulk.actor_id == user.pk
        assert second is not None
        assert third is not None

    def test_password_change(self, user: User) -> None:
        session = do_login(user.email)
        headers: dict[str, Any] = session.auth
        response = Client().post(
            "/api/v1/auth/password/change/",
            {"current_password": PASSWORD, "new_password": NEW_PASSWORD},
            content_type="application/json",
            **headers,
        )
        assert response.status_code == 200
        [changed] = rows(action="auth.password.changed")
        assert changed.changes == {"password": {"changed": True}}
        assert changed.metadata["previous_session_id"]
        assert rows(action="auth.sessions.revoked")[0].metadata["reason"] == "password_changed"
        Client().post(
            "/api/v1/auth/password/change/",
            {"current_password": "wrong", "new_password": NEW_PASSWORD},
            content_type="application/json",
            **headers,
        )

    def test_password_reset_lifecycle(self, user: User) -> None:
        Client().post(
            "/api/v1/auth/password/reset/", {"email": user.email}, content_type="application/json"
        )
        deliver_due(batch_size=5)
        [body] = [str(m.body) for m in mail.outbox]
        match = re.search(r"#uid=([^&\s]+)&token=(\S+)", body)
        assert match
        Client().post(
            "/api/v1/auth/password/reset/confirm/",
            {"uid": match[1], "token": match[2], "new_password": NEW_PASSWORD},
            content_type="application/json",
        )
        Client().post(
            "/api/v1/auth/password/reset/confirm/",
            {"uid": match[1], "token": match[2], "new_password": NEW_PASSWORD},
            content_type="application/json",
        )
        assert [a for a in _actions() if a.startswith("auth.password_reset")] == [
            "auth.password_reset.requested",
            "auth.password_reset.email_delivered",
            "auth.password_reset.completed",
            "auth.password_reset.failed",
        ]
        [completed] = rows(action="auth.password_reset.completed")
        assert completed.changes == {"password": {"changed": True}}
        text = all_rows_text()
        for secret in (match[2], match[1], NEW_PASSWORD, user.password):
            assert secret not in text


@pytest.mark.django_db(transaction=True)
def test_refresh_replay_revocation_and_audit_commit_together(user: User) -> None:
    session = do_login(user.email)
    stolen = session.refresh_token
    assert session.refresh().status_code == 200
    session.client.cookies[REFRESH_COOKIE] = stolen
    response = session.refresh()

    assert response.status_code == 401
    stored = AuthSession.objects.get(user=user)  # read back after the request committed
    assert stored.revoke_reason == RevokeReason.REFRESH_REUSE
    [row] = rows(action="auth.refresh.reuse_detected")
    assert row.outcome == "failure"
    assert (row.target_type, row.target_id) == ("session", str(stored.pk))
    assert row.actor_id == user.pk


@pytest.mark.django_db(transaction=True)
def test_refresh_replay_audit_failure_keeps_the_session_unrevoked(
    user: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revocation and its audit record are one unit: neither commits without the other."""
    session = do_login(user.email)
    stolen = session.refresh_token
    session.refresh()
    real_save = AuditLog.save

    def fail_for_replay(self: AuditLog, *args: Any, **kwargs: Any) -> None:
        if self.action == "auth.refresh.reuse_detected":
            raise RuntimeError("audit storage unavailable")
        real_save(self, *args, **kwargs)

    monkeypatch.setattr(AuditLog, "save", fail_for_replay)
    with pytest.raises(RuntimeError, match="audit storage"):
        rotate(stolen)
    assert AuthSession.objects.get(user=user).revoked_at is None
    assert rows(action="auth.refresh.reuse_detected") == []


@pytest.mark.django_db
class TestAdminEvents:
    @pytest.fixture
    def superuser(self) -> User:
        return User.objects.create_superuser("root@example.org", PASSWORD, full_name="Root")

    def _client(self, admin_user: User) -> Client:
        client = Client()
        client.force_login(admin_user)
        return client

    def test_account_lifecycle_through_the_admin(self, superuser: User, user: User) -> None:
        client = self._client(superuser)
        url = f"/admin/accounts/user/{user.pk}/change/"
        base = {"email": user.email, "full_name": user.full_name, "is_active": "on"}
        client.post(url, {**base, "is_staff": "on"})
        client.post(
            url,
            {
                **base,
                "is_staff": "on",
                "user_permissions": [Permission.objects.get(codename="view_organization").pk],
            },
        )
        client.post(url, {"email": user.email, "full_name": user.full_name, "is_staff": "on"})
        [updated] = rows(action="auth.account.updated")
        assert updated.changes == {"is_staff": {"from": False, "to": True}}
        assert rows(action="auth.account.permissions_changed")[0].metadata == {
            "changed_fields": ["user_permissions"]
        }
        [deactivated] = rows(action="auth.account.deactivated")
        assert deactivated.actor_id == superuser.pk
        assert deactivated.changes == {"is_active": {"from": True, "to": False}}
        client.post(url, {**base, "is_staff": "on"})  # reactivation
        assert rows(action="auth.account.updated")[-1].changes == {
            "is_active": {"from": False, "to": True}
        }

    def test_account_creation_and_admin_password_change(self, superuser: User) -> None:
        client = self._client(superuser)
        client.post(
            "/admin/accounts/user/add/",
            {
                "email": "new@example.org",
                "full_name": "New",
                "password1": NEW_PASSWORD,
                "password2": NEW_PASSWORD,
            },
        )
        created = User.objects.get(email="new@example.org")
        [row] = rows(action="auth.account.created")
        assert (row.actor_id, row.target_id) == (superuser.pk, str(created.pk))
        client.post(
            f"/admin/accounts/user/{created.pk}/password/",
            {"password1": "Another-Passphrase-99", "password2": "Another-Passphrase-99"},
        )
        [changed] = rows(action="auth.password.changed_by_admin")
        assert changed.actor_id == superuser.pk
        assert changed.changes == {"password": {"changed": True}}
        assert "Another-Passphrase-99" not in all_rows_text()

    def test_admin_login_events(self, superuser: User) -> None:
        client = Client()
        client.post("/admin/login/", {"username": superuser.email, "password": "wrong"})
        client.post("/admin/login/", {"username": superuser.email, "password": PASSWORD})
        assert [a for a in _actions() if a.startswith("auth.admin_login")] == [
            "auth.admin_login.failed",
            "auth.admin_login.succeeded",
        ]

    def test_admin_session_revocation_names_the_admin(self, superuser: User, user: User) -> None:
        do_login(user.email)
        target = AuthSession.objects.get(user=user)
        self._client(superuser).post(
            "/admin/accounts/authsession/",
            {"action": "revoke_selected", "_selected_action": [str(target.pk)]},
        )
        [row] = rows(action="auth.session.revoked")
        assert row.actor_id == superuser.pk


@pytest.mark.django_db
def test_known_secrets_never_reach_audit_rows(user: User) -> None:
    session = do_login(user.email)
    access, refresh = session.access_token, session.refresh_token
    csrf = session.csrf_headers()["HTTP_X_CSRFTOKEN"]
    session.refresh()
    session.client.post(LOGOUT_URL, **session.csrf_headers())
    Client().post(
        LOGIN_URL,
        {"email": user.email, "password": "Wrong-Secret-Marker-55"},
        content_type="application/json",
    )
    text = all_rows_text()
    assert _actions()
    for secret in (PASSWORD, "Wrong-Secret-Marker-55", access, refresh, csrf, user.password):
        assert secret not in text
