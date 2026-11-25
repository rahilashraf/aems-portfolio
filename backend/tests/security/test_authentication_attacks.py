"""Authentication attack suite (plan §4.2-4.4, §10, ADR-0004, ADR-0013, ADR-0019).

Every attack is made over HTTP against a protected endpoint (``GET /api/v1/auth/me/``), so the
whole stack is exercised: header parsing, signature and claim validation, the server-side session
check, and the Problem Details response.
"""

import base64
import json
import threading
import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import jwt
import pytest
from django.conf import settings
from django.db import connections
from django.test import Client, override_settings
from django.utils import timezone

from apps.accounts.models import AuthSession, User
from apps.accounts.sessions import create_session
from apps.accounts.tests.conftest import PASSWORD, REFRESH_COOKIE, Session, do_login
from apps.accounts.tokens import password_reset_tokens


def _headers(session: Any) -> dict[str, Any]:
    return dict(session.auth)


pytestmark = [
    pytest.mark.django_db,
    # Short or wrong keys are the point of some attacks below.
    pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning"),
]
ME = "/api/v1/auth/me/"
REFRESH = "/api/v1/auth/token/refresh/"
NEW_PASSWORD = "Fresh-Passphrase-For-Tests-91"


@pytest.fixture
def victim(make_user: Callable[..., User]) -> User:
    return make_user("victim@example.org")


def _me(token: str) -> Any:
    return Client().get(ME, HTTP_AUTHORIZATION=f"Bearer {token}")


def _claims(user: User, session: AuthSession, **overrides: Any) -> dict[str, Any]:
    now = int(timezone.now().timestamp())
    claims: dict[str, Any] = {
        "type": "access",
        "sub": str(user.pk),
        "sid": str(session.pk),
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + 300,
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not ...}


def _sign(claims: dict[str, Any], key: str | None = None, algorithm: str = "HS256") -> str:
    return jwt.encode(claims, key or settings.SIMPLE_JWT["SIGNING_KEY"], algorithm=algorithm)


def _b64(data: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _assert_rejected(response: Any) -> None:
    assert response.status_code == 401, response.content
    assert response["WWW-Authenticate"].startswith("Bearer")
    assert response.json()["code"] == "authentication_failed"


# ------------------------------------------------------------------------------- JWT validation
class TestForgedAndMalformedTokens:
    def test_correctly_signed_baseline_is_accepted(self, victim: User) -> None:
        session = create_session(victim, client_ip=None).session
        assert _me(_sign(_claims(victim, session))).status_code == 200

    def test_modified_payload_keeps_the_old_signature(self, victim: User, make_user: Any) -> None:
        attacker = make_user("attacker@example.org")
        issued = create_session(attacker, client_ip=None)
        header, _payload, signature = issued.access_token.split(".")
        forged_payload = _b64(
            {
                **jwt.decode(issued.access_token, options={"verify_signature": False}),
                "sub": str(victim.pk),
            }
        )
        _assert_rejected(_me(f"{header}.{forged_payload}.{signature}"))

    def test_invalid_signature_and_other_keys(self, victim: User) -> None:
        session = create_session(victim, client_ip=None).session
        claims = _claims(victim, session)
        for key in ("wrong-key-" * 8, settings.SECRET_KEY, "x"):
            _assert_rejected(_me(_sign(claims, key=key)))

    def test_unsigned_alg_none(self, victim: User) -> None:
        session = create_session(victim, client_ip=None).session
        claims = _claims(victim, session)
        for alg in ("none", "None", "NONE"):
            token = f"{_b64({'alg': alg, 'typ': 'JWT'})}.{_b64(claims)}."
            _assert_rejected(_me(token))

    @pytest.mark.parametrize("algorithm", ["HS384", "HS512"])
    def test_unexpected_algorithms_with_the_real_key(self, victim: User, algorithm: str) -> None:
        session = create_session(victim, client_ip=None).session
        _assert_rejected(_me(_sign(_claims(victim, session), algorithm=algorithm)))

    def test_algorithm_confusion_header(self, victim: User) -> None:
        session = create_session(victim, client_ip=None).session
        good = _sign(_claims(victim, session))
        _header, payload, signature = good.split(".")
        for alg in ("RS256", "ES256", "PS256"):
            _assert_rejected(_me(f"{_b64({'alg': alg, 'typ': 'JWT'})}.{payload}.{signature}"))

    def test_expired(self, victim: User) -> None:
        session = create_session(victim, client_ip=None).session
        now = int(timezone.now().timestamp())
        _assert_rejected(_me(_sign(_claims(victim, session, iat=now - 700, exp=now - 1))))

    @pytest.mark.parametrize("ahead", [5, 3600])
    def test_future_dated_issue_time(self, victim: User, ahead: int) -> None:
        """PyJWT verifies ``iat`` with the configured leeway (0): a token "issued" in the future,
        which would otherwise outlive a password change, is rejected."""
        assert settings.SIMPLE_JWT["LEEWAY"] == 0
        session = create_session(victim, client_ip=None).session
        now = int(timezone.now().timestamp())
        _assert_rejected(_me(_sign(_claims(victim, session, iat=now + ahead, exp=now + 7200))))

    @pytest.mark.parametrize(
        "overrides",
        [
            {"iat": "yesterday"},
            {"exp": "never"},
            {"iat": 10**20},
            {"exp": None},
            {"sub": "not-a-uuid"},
            {"sid": 12345},
            {"sub": None},
            {"type": "refresh"},
            {"type": "ACCESS"},
            {"type": None},
        ],
    )
    def test_malformed_claims(self, victim: User, overrides: dict[str, Any]) -> None:
        session = create_session(victim, client_ip=None).session
        _assert_rejected(_me(_sign(_claims(victim, session, **overrides))))

    @pytest.mark.parametrize("claim", ["sub", "sid", "jti", "iat", "exp", "type"])
    def test_missing_required_claims(self, victim: User, claim: str) -> None:
        session = create_session(victim, client_ip=None).session
        _assert_rejected(_me(_sign(_claims(victim, session, **{claim: ...}))))

    def test_issuer_and_audience_when_configured(self, victim: User, monkeypatch: Any) -> None:
        from rest_framework_simplejwt.settings import api_settings  # noqa: PLC0415
        from rest_framework_simplejwt.state import token_backend  # noqa: PLC0415

        session = create_session(victim, client_ip=None).session
        monkeypatch.setattr(token_backend, "issuer", "https://api.example.org")
        monkeypatch.setattr(token_backend, "audience", "aems")
        monkeypatch.setattr(api_settings, "ISSUER", "https://api.example.org")
        monkeypatch.setattr(api_settings, "AUDIENCE", "aems")
        good = {"iss": "https://api.example.org", "aud": "aems"}
        assert _me(_sign(_claims(victim, session, **good))).status_code == 200
        for bad in (
            {"iss": "https://evil.example", "aud": "aems"},
            {"iss": "https://api.example.org", "aud": "other"},
            {},
        ):
            _assert_rejected(_me(_sign(_claims(victim, session, **bad))))

    def test_unknown_session_and_nonexistent_user(self, victim: User) -> None:
        session = create_session(victim, client_ip=None).session
        _assert_rejected(_me(_sign(_claims(victim, session, sid=str(uuid.uuid4())))))
        _assert_rejected(_me(_sign(_claims(victim, session, sub=str(uuid.uuid4())))))

    def test_cross_user_session_identifier(self, victim: User, make_user: Any) -> None:
        attacker = make_user("attacker@example.org")
        victim_session = create_session(victim, client_ip=None).session
        _assert_rejected(_me(_sign(_claims(attacker, victim_session))))

    def test_refresh_token_is_not_an_access_token(self, victim: User) -> None:
        issued = create_session(victim, client_ip=None)
        _assert_rejected(_me(issued.refresh_token))

    @pytest.mark.parametrize(
        "header",
        ["Bearer", "Bearer a b", "bearer", "Token abc", "Bearer éé", "Bearer " + "a" * 9000],
    )
    def test_malformed_authorization_headers(self, header: str, db: Any) -> None:
        response = Client().get(ME, HTTP_AUTHORIZATION=header)
        assert response.status_code == 401


# ------------------------------------------------------------------------------- lifecycle
class TestSessionLifecycle:
    def test_revocation_paths_invalidate_old_credentials_immediately(
        self, victim: User, make_user: Any
    ) -> None:
        # Logout.
        s = do_login(victim.email)
        s.client.post("/api/v1/auth/logout/", **s.csrf_headers())
        _assert_rejected(_me(s.access_token))
        assert s.client.post(REFRESH, **s.csrf_headers()).status_code == 401

    def test_session_specific_revocation(self, victim: User) -> None:
        keep, drop = do_login(victim.email), do_login(victim.email)
        drop_id = AuthSession.objects.filter(user=victim).order_by("-created_at").first()
        assert drop_id is not None
        response = Client().delete(f"/api/v1/auth/sessions/{drop_id.pk}/", **_headers(keep))
        assert response.status_code == 204
        _assert_rejected(_me(drop.access_token))
        assert drop.refresh().status_code == 401
        assert _me(keep.access_token).status_code == 200

    def test_revoke_other_sessions(self, victim: User) -> None:
        sessions = [do_login(victim.email) for _ in range(3)]
        current = sessions[0]
        response = Client().post("/api/v1/auth/sessions/revoke-others/", **_headers(current))
        assert response.json() == {"revoked": 2}
        for other in sessions[1:]:
            _assert_rejected(_me(other.access_token))
            assert other.refresh().status_code == 401
        assert _me(current.access_token).status_code == 200

    def test_password_change_revokes_every_old_credential(self, victim: User) -> None:
        a, b = do_login(victim.email), do_login(victim.email)
        response = Client().post(
            "/api/v1/auth/password/change/",
            {"current_password": PASSWORD, "new_password": NEW_PASSWORD},
            content_type="application/json",
            **_headers(a),
        )
        assert response.status_code == 200
        for old in (a, b):
            _assert_rejected(_me(old.access_token))
            assert old.refresh().status_code == 401
        assert _me(response.json()["access_token"]).status_code == 200

    def test_password_reset_revokes_every_old_credential(self, victim: User) -> None:
        from django.utils.encoding import force_bytes  # noqa: PLC0415
        from django.utils.http import urlsafe_base64_encode  # noqa: PLC0415

        s = do_login(victim.email)
        fresh = User.objects.get(pk=victim.pk)  # login updated last_login (bound in the token)
        response = Client().post(
            "/api/v1/auth/password/reset/confirm/",
            {
                "uid": urlsafe_base64_encode(force_bytes(fresh.pk)),
                "token": password_reset_tokens.make_token(fresh),
                "new_password": NEW_PASSWORD,
            },
            content_type="application/json",
        )
        assert response.status_code == 204
        _assert_rejected(_me(s.access_token))
        assert s.refresh().status_code == 401

    def test_deactivation_revokes_every_old_credential(self, victim: User) -> None:
        from apps.accounts.services import deactivate_user  # noqa: PLC0415

        s = do_login(victim.email)
        deactivate_user(victim)
        _assert_rejected(_me(s.access_token))
        assert s.refresh().status_code == 401
        response = Client().post(
            "/api/v1/auth/login/",
            {"email": victim.email, "password": PASSWORD},
            content_type="application/json",
        )
        assert response.status_code == 401

    def test_refresh_rotation_and_replay_revokes_the_family(self, victim: User) -> None:
        s = do_login(victim.email)
        stolen = s.refresh_token
        assert s.refresh().status_code == 200
        attacker = Client(enforce_csrf_checks=True)
        attacker.cookies[REFRESH_COOKIE] = stolen
        replay = Session(client=attacker, access_token="")
        assert replay.refresh().status_code == 401
        # The legitimate holder's newer token is now dead too (whole family revoked).
        assert s.refresh().status_code == 401
        assert AuthSession.objects.get(user=victim).revoke_reason == "refresh_reuse"

    @pytest.mark.django_db(transaction=True)
    def test_concurrent_refresh_lets_exactly_one_win(self, victim: User) -> None:
        s = do_login(victim.email)
        cookie, headers = s.refresh_token, s.csrf_headers()
        csrf = s.client.cookies["csrftoken"].value
        barrier = threading.Barrier(4)
        codes: list[int] = []

        def worker() -> None:
            client = Client(enforce_csrf_checks=True)
            client.cookies[REFRESH_COOKIE] = cookie
            client.cookies["csrftoken"] = csrf
            barrier.wait(timeout=10)
            try:
                codes.append(client.post(REFRESH, **headers).status_code)
            finally:
                connections.close_all()

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        assert sorted(codes) == [200, 401, 401, 401]


# --------------------------------------------------------------------------- cookies, CSRF, CORS
class TestCookiesCsrfAndCors:
    def test_refresh_cookie_attributes(self, victim: User) -> None:
        response = Client().post(
            "/api/v1/auth/login/",
            {"email": victim.email, "password": PASSWORD},
            content_type="application/json",
        )
        cookie = response.cookies[REFRESH_COOKIE]
        assert cookie["httponly"] is True
        assert cookie["secure"] is True
        assert cookie["samesite"] == "Strict"
        assert cookie["path"] == "/api/v1/auth/"
        assert REFRESH_COOKIE not in response.content.decode()
        assert cookie.value not in response.content.decode()

    def test_csrf_cookie_attributes(self, db: Any) -> None:
        cookie = Client().get("/api/v1/auth/csrf/").cookies["csrftoken"]
        assert cookie["samesite"] == "Strict"
        assert not cookie["httponly"]  # read by the SPA for the double-submit header

    @pytest.mark.parametrize(
        "headers",
        [
            {},
            {"HTTP_X_CSRFTOKEN": "wrong" * 8, "HTTP_ORIGIN": "http://testserver"},
            {"HTTP_ORIGIN": "https://evil.example"},
            {"HTTP_ORIGIN": "null"},
            {"HTTP_ORIGIN": "http://testserver.evil.example"},
        ],
    )
    def test_cookie_endpoints_reject_cross_site_requests(
        self, victim: User, headers: dict[str, str]
    ) -> None:
        s = do_login(victim.email)
        good = s.csrf_headers()
        attempt = {**good, **headers} if headers else {}
        if "HTTP_X_CSRFTOKEN" not in headers and headers:
            attempt["HTTP_X_CSRFTOKEN"] = good["HTTP_X_CSRFTOKEN"]
        for path in (REFRESH, "/api/v1/auth/logout/"):
            response = s.client.post(path, **attempt)
            assert response.status_code == 403, (path, headers)
            assert response.json()["code"] == "csrf_failed"
        # Nothing happened: the session is still active and refreshes normally.
        assert s.refresh().status_code == 200

    @override_settings(
        CORS_ALLOWED_ORIGINS=["https://app.example.org"], CORS_ALLOW_CREDENTIALS=True
    )
    def test_cors_allowlist_and_credentials(self, db: Any) -> None:
        allowed = Client().options(
            REFRESH,
            HTTP_ORIGIN="https://app.example.org",
            HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST",
        )
        assert allowed["Access-Control-Allow-Origin"] == "https://app.example.org"
        assert allowed["Access-Control-Allow-Credentials"] == "true"
        for origin in ("https://evil.example", "null", "https://app.example.org.evil.example"):
            denied = Client().options(
                REFRESH, HTTP_ORIGIN=origin, HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST"
            )
            assert "Access-Control-Allow-Origin" not in denied
            assert "Access-Control-Allow-Credentials" not in denied
            simple = Client().get("/api/v1/", HTTP_ORIGIN=origin)
            assert "Access-Control-Allow-Origin" not in simple

    def test_no_cross_origin_access_by_default(self, db: Any) -> None:
        response = Client().get("/api/v1/", HTTP_ORIGIN="https://app.example.org")
        assert "Access-Control-Allow-Origin" not in response

    def test_login_rejects_simple_cross_site_content_types(self, victim: User) -> None:
        """A cross-site form can send these without a CORS preflight; none may sign in."""
        for content_type, body in (
            ("application/x-www-form-urlencoded", f"email={victim.email}&password={PASSWORD}"),
            ("text/plain", json.dumps({"email": victim.email, "password": PASSWORD})),
            ("multipart/form-data; boundary=b", "--b--"),
        ):
            response = Client().generic(
                "POST", "/api/v1/auth/login/", body, content_type=content_type
            )
            assert response.status_code == 415
            assert REFRESH_COOKIE not in response.cookies


# ------------------------------------------------------------------------------- lifetimes
def test_token_lifetimes_and_session_cap() -> None:
    assert settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"] == timedelta(minutes=10)
    assert settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"] == timedelta(days=7)
    assert settings.AUTH_SESSION_ABSOLUTE_LIFETIME_SECONDS == 30 * 24 * 3600
    assert settings.SIMPLE_JWT["SIGNING_KEY"] != settings.SECRET_KEY
