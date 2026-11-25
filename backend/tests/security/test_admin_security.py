"""Platform admin attacks (review findings AEMS-021 and AEMS-022, ADR-0019).

AEMS-021: a staff account holding ``accounts.change_user`` (but not superuser) could change the
password, email address or active state of superusers and other staff, i.e. take over a more
privileged account; users and sessions could also be deleted through the admin, bypassing the
audited deactivation and revocation services.

AEMS-022: email changes made in the admin were not audited.
"""

from typing import Any

import pytest
from django.contrib.auth.models import Permission
from django.test import Client

from apps.accounts.models import AuthSession, User
from apps.accounts.sessions import create_session
from apps.accounts.tests.conftest import PASSWORD
from apps.audit.models import AuditLog

pytestmark = pytest.mark.django_db
ADMIN = "/admin/accounts/"
NEW_PASSWORD = "Another-Strong-Passphrase-77"


@pytest.fixture
def superuser() -> User:
    return User.objects.create_superuser("root@example.org", PASSWORD, full_name="Root")


def _staff(email: str, *codenames: str) -> User:
    user = User.objects.create_user(email, PASSWORD, full_name="Staff", is_staff=True)
    user.user_permissions.add(*Permission.objects.filter(codename__in=codenames))
    return User.objects.get(pk=user.pk)


@pytest.fixture
def operator() -> User:
    """Staff with every account model permission, but not a superuser."""
    return _staff(
        "operator@example.org",
        "view_user",
        "change_user",
        "delete_user",
        "view_authsession",
        "change_authsession",
        "delete_authsession",
    )


def _client(user: User) -> Client:
    client = Client()
    client.force_login(user)
    return client


def _change(client: Client, target: User, **fields: Any) -> Any:
    data = {
        "email": target.email,
        "full_name": target.full_name,
        "is_active": "on" if target.is_active else "",
        **fields,
    }
    return client.post(f"{ADMIN}user/{target.pk}/change/", {k: v for k, v in data.items() if v})


# ------------------------------------------------------------------------------- AEMS-021
@pytest.mark.parametrize("target_kind", ["superuser", "staff"])
def test_staff_cannot_take_over_privileged_accounts(
    operator: User, superuser: User, target_kind: str
) -> None:
    target = superuser if target_kind == "superuser" else _staff("other@example.org", "view_user")
    before = User.objects.values("email", "password", "is_active").get(pk=target.pk)
    client = _client(operator)

    password_view = f"{ADMIN}user/{target.pk}/password/"
    assert client.get(password_view).status_code == 403
    response = client.post(password_view, {"password1": NEW_PASSWORD, "password2": NEW_PASSWORD})
    assert response.status_code == 403
    response = _change(client, target, email="attacker@evil.test")
    assert response.status_code == 403
    response = _change(client, target, is_active="")
    assert response.status_code == 403

    assert User.objects.values("email", "password", "is_active").get(pk=target.pk) == before
    assert not AuditLog.objects.filter(target_id=str(target.pk)).exists()
    # The change form is view-only for the operator.
    page = client.get(f"{ADMIN}user/{target.pk}/change/")
    assert page.status_code == 200
    assert b'name="email"' not in page.content


def test_staff_still_manages_ordinary_accounts(operator: User) -> None:
    target = User.objects.create_user("plain@example.org", PASSWORD, full_name="Plain")
    client = _client(operator)
    response = client.post(
        f"{ADMIN}user/{target.pk}/password/",
        {"password1": NEW_PASSWORD, "password2": NEW_PASSWORD},
    )
    assert response.status_code == 302
    assert User.objects.get(pk=target.pk).check_password(NEW_PASSWORD)


def test_superusers_can_change_privileged_accounts(superuser: User) -> None:
    target = _staff("other@example.org", "view_user")
    response = _client(superuser).post(
        f"{ADMIN}user/{target.pk}/password/",
        {"password1": NEW_PASSWORD, "password2": NEW_PASSWORD},
    )
    assert response.status_code == 302
    assert AuditLog.objects.filter(action="auth.password.changed_by_admin").exists()


def test_staff_cannot_promote_themselves(operator: User) -> None:
    response = _change(_client(operator), operator, is_superuser="on", is_staff="on")
    assert response.status_code == 403
    assert not User.objects.get(pk=operator.pk).is_superuser


@pytest.mark.parametrize("model", ["user", "authsession"])
def test_admin_never_deletes_accounts_or_sessions(
    superuser: User, operator: User, model: str
) -> None:
    victim = User.objects.create_user("victim@example.org", PASSWORD, full_name="Victim")
    session = create_session(victim, client_ip=None).session
    obj = victim if model == "user" else session
    for actor in (superuser, operator):
        client = _client(actor)
        assert client.get(f"{ADMIN}{model}/{obj.pk}/delete/").status_code == 403
        assert client.post(f"{ADMIN}{model}/{obj.pk}/delete/", {"post": "yes"}).status_code == 403
        changelist = client.get(f"{ADMIN}{model}/")
        assert b"delete_selected" not in changelist.content
        client.post(
            f"{ADMIN}{model}/",
            {"action": "delete_selected", "_selected_action": [str(obj.pk)], "post": "yes"},
        )
    assert User.objects.filter(pk=victim.pk).exists()
    assert AuthSession.objects.filter(pk=session.pk, revoked_at__isnull=True).exists()


# ------------------------------------------------------------------------------- AEMS-022
def test_admin_email_change_is_audited(superuser: User) -> None:
    target = User.objects.create_user("before@example.org", PASSWORD, full_name="Target")
    response = _change(_client(superuser), target, email="After@Example.org")
    assert response.status_code == 302
    assert User.objects.get(pk=target.pk).email == "after@example.org"
    entry = AuditLog.objects.get(action="auth.account.updated", target_id=str(target.pk))
    assert entry.actor_id == superuser.pk
    assert entry.changes == {"email": {"from": "before@example.org", "to": "after@example.org"}}


def test_view_only_staff_cannot_change_any_account() -> None:
    viewer = _staff("viewer@example.org", "view_user")
    target = User.objects.create_user("plain@example.org", PASSWORD, full_name="Plain")
    client = _client(viewer)
    response = client.post(
        f"{ADMIN}user/{target.pk}/password/",
        {"password1": NEW_PASSWORD, "password2": NEW_PASSWORD},
    )
    assert response.status_code == 403
    assert _change(client, target, full_name="Changed").status_code == 403
    assert User.objects.get(pk=target.pk).full_name == "Plain"


# ------------------------------------------------------------------------------- AEMS-025 (admin)
ADMIN_LOGIN = "/admin/login/"
LIMITS = {"login_ip": (2, 300), "login_account": (100, 900), "login_ip_account": (100, 900)}


@pytest.mark.parametrize("attempts", [3, 25])
def test_rate_limited_admin_logins_write_one_durable_event_per_window(
    attempts: int, events: Any
) -> None:
    """Denied admin sign-ins follow the bounded pattern of the API limiter: the first refusal of a
    window is a durable audit record, later ones are structured log events only. The response
    and the enforcement are unchanged."""
    staff = _staff("limited@example.org", "view_user")
    from django.test import override_settings  # noqa: PLC0415

    responses = []
    with override_settings(AUTH_RATE_LIMITS=LIMITS):
        for _ in range(attempts):
            client = Client()
            responses.append(
                client.post(ADMIN_LOGIN, {"username": staff.email, "password": "Wrong-Password-1"})
            )
        # Enforcement is unchanged: even the correct password is refused in the window.
        refused = Client().post(ADMIN_LOGIN, {"username": staff.email, "password": PASSWORD})

    denied = [*responses[2:], refused]
    for response in denied:
        assert response.status_code == 200  # the login form is re-rendered
        assert b"Too many sign-in attempts" in response.content
        assert "_auth_user_id" not in response.wsgi_request.session
    assert AuditLog.objects.filter(action="auth.admin_login.rate_limited").count() == 1
    assert AuditLog.objects.filter(action="auth.admin_login.failed").count() == 2
    first = AuditLog.objects.get(action="auth.admin_login.rate_limited")
    assert first.metadata["subject_digest"]
    assert first.ip_address == "127.0.0.1"
    # Every refusal remains visible in the security-event log stream.
    logged = [e for e in events if e.name == "auth.admin_login.rate_limited"]
    assert len(logged) == len(denied)
    assert all(e.subject_digest == first.metadata["subject_digest"] for e in logged)


def test_backed_off_admin_logins_stay_bounded_by_the_limiter(events: Any) -> None:
    """Locked-out (backoff) attempts are counted by the limiter before they are recorded, so their
    durable records are bounded by the window's limit as well."""
    staff = _staff("backoff@example.org", "view_user")
    from django.test import override_settings  # noqa: PLC0415

    with override_settings(
        AUTH_RATE_LIMITS={
            "login_ip": (6, 300),
            "login_account": (100, 900),
            "login_ip_account": (100, 900),
        },
        AUTH_LOGIN_BACKOFF={"threshold": 2, "base_seconds": 60, "cap_seconds": 60},
    ):
        for _ in range(40):
            Client().post(ADMIN_LOGIN, {"username": staff.email, "password": "Wrong-Password-1"})
    durable = AuditLog.objects.filter(action__startswith="auth.admin_login.")
    # 2 failures, 4 locked (backoff) refusals within the limit of 6, then 1 first rate-limit denial.
    assert durable.filter(action="auth.admin_login.failed").count() == 2
    assert durable.filter(action="auth.admin_login.rate_limited").count() == 5
    assert durable.count() == 7
