"""Platform admin, security events, client IP resolution, schema and production settings."""

from io import StringIO
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from django.core.management import call_command
from django.db import transaction
from django.test import Client, override_settings

from apps.accounts.models import AuthSession, RevokeReason, User
from apps.core import security_events
from apps.core.net import client_ip

from .conftest import PASSWORD, do_login

ADMIN = "/admin/"


@pytest.fixture
def superuser(db: Any) -> User:
    return User.objects.create_superuser("root@example.org", PASSWORD, full_name="Root")


@pytest.fixture
def staff(db: Any) -> User:
    from django.contrib.auth.models import Permission  # noqa: PLC0415

    user = User.objects.create_user("staff@example.org", PASSWORD, full_name="Staff", is_staff=True)
    user.user_permissions.add(*Permission.objects.filter(codename__in=["view_user", "change_user"]))
    return user


def _admin_client(user: User) -> Client:
    client = Client()
    client.force_login(user)
    return client


@pytest.mark.django_db
class TestAdmin:
    def test_regular_users_cannot_sign_in(self, make_user: Any) -> None:
        make_user("normal@example.org")
        response = Client().post(
            f"{ADMIN}login/", {"username": "normal@example.org", "password": PASSWORD}
        )
        assert response.status_code == 200  # login form re-rendered with an error
        assert "_auth_user_id" not in Client().session

    def test_staff_can_sign_in_with_email(self, staff: User) -> None:
        client = Client()
        response = client.post(
            f"{ADMIN}login/", {"username": "STAFF@example.org", "password": PASSWORD}
        )
        assert response.status_code == 302

    @override_settings(
        AUTH_RATE_LIMITS={
            "login_ip": (2, 300),
            "login_account": (100, 900),
            "login_ip_account": (100, 900),
        }
    )
    def test_admin_login_is_rate_limited(self, staff: User, events: Any) -> None:
        client = Client()
        for _ in range(2):
            client.post(f"{ADMIN}login/", {"username": staff.email, "password": "wrong-pass-1"})
        response = client.post(f"{ADMIN}login/", {"username": staff.email, "password": PASSWORD})
        assert response.status_code == 200
        assert b"Too many sign-in attempts" in response.content
        assert "auth.admin_login.rate_limited" in [e.name for e in events]

    def test_change_form_never_shows_password_hash(self, superuser: User, user: User) -> None:
        response = _admin_client(superuser).get(f"{ADMIN}accounts/user/{user.pk}/change/")
        assert response.status_code == 200
        content = response.content.decode()
        assert user.password not in content
        assert "md5$" not in content
        assert "argon2$" not in content
        assert 'name="password"' not in content

    def test_staff_cannot_escalate(self, staff: User, user: User) -> None:
        client = _admin_client(staff)
        form = client.get(f"{ADMIN}accounts/user/{staff.pk}/change/").content.decode()
        assert 'name="is_superuser"' not in form
        assert 'name="is_staff"' not in form
        client.post(
            f"{ADMIN}accounts/user/{staff.pk}/change/",
            {
                "email": staff.email,
                "full_name": "Staff",
                "is_active": "on",
                "is_superuser": "on",
                "is_staff": "on",
            },
        )
        staff.refresh_from_db()
        assert staff.is_superuser is False

    def test_deactivation_through_admin_revokes_sessions(
        self, superuser: User, user: User, django_capture_on_commit_callbacks: Any
    ) -> None:
        session = do_login(user.email)
        response = _admin_client(superuser).post(
            f"{ADMIN}accounts/user/{user.pk}/change/",
            {"email": user.email, "full_name": user.full_name, "is_staff": "", "is_superuser": ""},
        )
        assert response.status_code == 302, response.content[:500]
        user.refresh_from_db()
        assert user.is_active is False
        assert AuthSession.objects.get(user=user).revoke_reason == RevokeReason.DEACTIVATED
        assert (
            Client()
            .get("/api/v1/auth/me/", HTTP_AUTHORIZATION=f"Bearer {session.access_token}")
            .status_code
            == 401
        )

    def test_admin_password_change_revokes_sessions(self, superuser: User, user: User) -> None:
        session = do_login(user.email)
        new = "Admin-Set-Passphrase-123"
        response = _admin_client(superuser).post(
            f"{ADMIN}accounts/user/{user.pk}/password/",
            {"password1": new, "password2": new, "usable_password": "true"},
        )
        assert response.status_code == 302, response.content[:500]
        user.refresh_from_db()
        assert user.check_password(new)
        assert AuthSession.objects.get(user=user).revoke_reason == RevokeReason.PASSWORD_CHANGED
        assert session.refresh().status_code == 401

    def test_add_user_through_admin(self, superuser: User) -> None:
        response = _admin_client(superuser).post(
            f"{ADMIN}accounts/user/add/",
            {
                "email": " New.Staff@Example.org",
                "full_name": "New",
                "password1": "Strong-Admin-Pass-99",
                "password2": "Strong-Admin-Pass-99",
            },
        )
        assert response.status_code == 302, response.content[:800]
        created = User.objects.get(email="new.staff@example.org")
        assert created.password_changed_at is not None
        dup = _admin_client(superuser).post(
            f"{ADMIN}accounts/user/add/",
            {
                "email": "NEW.staff@example.org",
                "full_name": "Dup",
                "password1": "Strong-Admin-Pass-99",
                "password2": "Strong-Admin-Pass-99",
            },
        )
        assert dup.status_code == 200
        assert b"already exists" in dup.content

    def test_add_user_password_rules(self, superuser: User) -> None:
        client = _admin_client(superuser)
        mismatch = client.post(
            f"{ADMIN}accounts/user/add/",
            {
                "email": "m@example.org",
                "full_name": "M",
                "password1": "Strong-Admin-Pass-99",
                "password2": "other-Strong-Pass-1",
            },
        )
        weak = client.post(
            f"{ADMIN}accounts/user/add/",
            {
                "email": "w@example.org",
                "full_name": "W",
                "password1": "short",
                "password2": "short",
            },
        )
        assert b"didn" in mismatch.content
        assert weak.status_code == 200
        assert not User.objects.filter(email="w@example.org").exists()

    def test_session_admin_is_read_only_with_revoke_action(
        self, superuser: User, user: User
    ) -> None:
        do_login(user.email)
        session = AuthSession.objects.get(user=user)
        client = _admin_client(superuser)
        assert client.get(f"{ADMIN}accounts/authsession/add/").status_code == 403
        page = client.get(f"{ADMIN}accounts/authsession/{session.pk}/change/").content.decode()
        assert session.refresh_jti_hash not in page
        client.post(
            f"{ADMIN}accounts/authsession/",
            {"action": "revoke_selected", "_selected_action": [str(session.pk)]},
        )
        session.refresh_from_db()
        assert session.revoke_reason == RevokeReason.USER_REVOKED

    def test_user_change_form_rejects_duplicate_email(
        self, superuser: User, make_user: Any
    ) -> None:
        a, b = make_user("a@example.org"), make_user("b@example.org")
        response = _admin_client(superuser).post(
            f"{ADMIN}accounts/user/{b.pk}/change/",
            {"email": "A@example.org", "full_name": "B", "is_active": "on"},
        )
        assert response.status_code == 200
        assert b"already exists" in response.content
        assert a.email == "a@example.org"


@pytest.mark.django_db
class TestSecurityEvents:
    def test_after_commit_events_are_dropped_on_rollback(
        self, events: Any, django_capture_on_commit_callbacks: Any
    ) -> None:
        with django_capture_on_commit_callbacks(execute=True):
            try:
                with transaction.atomic():
                    security_events.emit_after_commit(
                        security_events.build_event("test.rolled_back", "success", user_id="u1")
                    )
                    raise RuntimeError
            except RuntimeError:
                pass
            with transaction.atomic():
                security_events.emit_after_commit(
                    security_events.build_event("test.committed", "success", user_id="u2")
                )
        assert [e.name for e in events] == ["test.committed"]

    def test_log_sink_renders_structured_event(self, json_logs: Any) -> None:
        security_events.log_security_event(
            "test.failure",
            outcome="failure",
            user_id="u1",
            client_ip="192.0.2.1",
            password="hunter2",
        )
        [record] = json_logs.events("test.failure")
        assert record["outcome"] == "failure"
        assert record["level"] == "warning"
        assert record["logger"] == "aems.security"
        assert "hunter2" not in json_logs.text

    def test_failing_sink_never_breaks_the_caller(self, json_logs: Any) -> None:
        def broken(_event: Any) -> None:
            raise RuntimeError("sink down")

        unregister = security_events.register_sink(broken)
        try:
            security_events.log_security_event("test.sink_failure", outcome="success")
        finally:
            unregister()
        [record] = json_logs.events("security.sink_failed")
        assert record["event_name"] == "test.sink_failure"
        assert record["error_type"] == "RuntimeError"


class TestClientIp:
    def _request(self, remote: str, forwarded: str | None = None) -> Any:
        meta = {"REMOTE_ADDR": remote}
        if forwarded is not None:
            meta["HTTP_X_FORWARDED_FOR"] = forwarded
        return SimpleNamespace(META=meta)

    def test_remote_addr_by_default(self) -> None:
        assert client_ip(self._request("192.0.2.10", "203.0.113.5")) == "192.0.2.10"

    @override_settings(TRUSTED_PROXY_COUNT=1)
    def test_trusted_single_proxy(self) -> None:
        assert client_ip(self._request("10.0.0.1", "spoofed, 203.0.113.5")) == "203.0.113.5"

    @override_settings(TRUSTED_PROXY_COUNT=2)
    def test_trusted_two_proxies(self) -> None:
        assert (
            client_ip(self._request("10.0.0.1", "1.1.1.1, 203.0.113.5, 10.0.0.9")) == "203.0.113.5"
        )

    @override_settings(TRUSTED_PROXY_COUNT=2)
    def test_too_few_hops_or_garbage_falls_back(self) -> None:
        assert client_ip(self._request("10.0.0.1", "203.0.113.5")) == "10.0.0.1"
        assert client_ip(self._request("10.0.0.1", "x, not-an-ip")) == "10.0.0.1"

    def test_invalid_remote_addr(self) -> None:
        assert client_ip(self._request("garbage")) is None


def test_schema_documents_bearer_auth_and_endpoints(db: Any) -> None:
    out = StringIO()
    call_command("spectacular", "--validate", "--fail-on-warn", stdout=out)
    schema = yaml.safe_load(out.getvalue())
    assert schema["components"]["securitySchemes"]["bearerAuth"]["scheme"] == "bearer"
    paths = set(schema["paths"])
    for path in (
        "/api/v1/auth/login/",
        "/api/v1/auth/token/refresh/",
        "/api/v1/auth/sessions/{session_id}/",
    ):
        assert path in paths
    login = schema["paths"]["/api/v1/auth/login/"]["post"]
    assert "401" in login["responses"]
    assert "security" not in login
    me = schema["paths"]["/api/v1/auth/me/"]["get"]
    assert me["security"] == [{"bearerAuth": []}]
    assert "401" in me["responses"]
    assert "x-aems-problem-401" not in yaml.safe_dump(schema)


def test_public_auth_endpoints_are_allowlisted() -> None:
    from django.conf import settings  # noqa: PLC0415

    public = set(settings.API_PUBLIC_ENDPOINTS)
    assert {"api-v1:auth:login", "api-v1:auth:token-refresh", "api-v1:auth:logout"} <= public
    assert "api-v1:auth:me" not in public
    assert "api-v1:auth:sessions" not in public
