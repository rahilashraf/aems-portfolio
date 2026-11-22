"""JWT claims/signature/expiry/type validation and per-request session checks."""

import uuid
from datetime import timedelta
from typing import Any

import jwt
import pytest
from django.conf import settings
from django.test import Client
from django.utils import timezone

from apps.accounts.models import AuthSession, RevokeReason, User
from apps.accounts.services import deactivate_user
from apps.accounts.sessions import create_session
from apps.accounts.tokens import (
    REQUIRED_CLAIMS,
    InvalidTokenError,
    decode_access_token,
    decode_refresh_token,
    issue_access_token,
)

from .conftest import ME_URL, Session

pytestmark = pytest.mark.django_db
KEY = settings.SIMPLE_JWT["SIGNING_KEY"]


def _encode(payload: dict[str, Any], key: str = KEY, algorithm: str = "HS256") -> str:
    return jwt.encode(payload, key, algorithm=algorithm)


def _claims(**overrides: Any) -> dict[str, Any]:
    now = int(timezone.now().timestamp())
    payload: dict[str, Any] = {
        "type": "access",
        "sub": str(uuid.uuid4()),
        "sid": str(uuid.uuid4()),
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + 600,
    }
    payload.update(overrides)
    return {k: v for k, v in payload.items() if v is not None}


class TestIssuedTokens:
    def test_access_token_claims(self, user: User) -> None:
        issued = create_session(user, client_ip="127.0.0.1")
        payload = jwt.decode(issued.access_token, KEY, algorithms=["HS256"])

        assert set(REQUIRED_CLAIMS) <= set(payload)
        assert payload["type"] == "access"
        assert payload["sub"] == str(user.pk)
        assert payload["sid"] == str(issued.session.id)
        assert payload["exp"] - payload["iat"] == 600  # 10 minutes

    def test_refresh_token_claims_and_cap(self, user: User) -> None:
        issued = create_session(user, client_ip=None)
        payload = jwt.decode(issued.refresh_token, KEY, algorithms=["HS256"])

        assert payload["type"] == "refresh"
        assert payload["exp"] - payload["iat"] == 7 * 24 * 3600
        assert payload["exp"] <= issued.session.expires_at.timestamp()
        session_lifetime = issued.session.expires_at - issued.session.created_at
        assert session_lifetime == timedelta(days=30)

    def test_refresh_expiry_never_exceeds_absolute_session_lifetime(self, user: User) -> None:
        issued = create_session(user, client_ip=None)
        session = issued.session
        session.expires_at = timezone.now() + timedelta(hours=1)
        from apps.accounts.sessions import _issue_pair  # noqa: PLC0415

        pair = _issue_pair(session, timezone.now())
        payload = jwt.decode(pair.refresh_token, KEY, algorithms=["HS256"])
        assert payload["exp"] <= session.expires_at.timestamp() + 1

    def test_jwt_key_is_dedicated(self) -> None:
        assert KEY != settings.SECRET_KEY

    def test_only_hash_of_refresh_jti_is_stored(self, user: User) -> None:
        issued = create_session(user, client_ip=None)
        jti = jwt.decode(issued.refresh_token, KEY, algorithms=["HS256"])["jti"]
        stored = AuthSession.objects.get(pk=issued.session.pk).refresh_jti_hash

        assert jti not in stored
        assert len(stored) == 64
        assert issued.refresh_token not in str(
            AuthSession.objects.filter(pk=issued.session.pk).values()
        )


class TestTokenValidation:
    def test_valid_token_decodes(self) -> None:
        claims = _claims()
        decoded = decode_access_token(_encode(claims))
        assert decoded.user_id == claims["sub"]

    @pytest.mark.parametrize(
        "token",
        [
            "",
            "not-a-jwt",
            "a.b.c",
        ],
    )
    def test_malformed(self, token: str) -> None:
        with pytest.raises(InvalidTokenError):
            decode_access_token(token)

    def test_wrong_signature_key(self) -> None:
        with pytest.raises(InvalidTokenError):
            decode_access_token(
                _encode(_claims(), key="another-key-0123456789-0123456789-0123456789")
            )

    def test_django_secret_key_cannot_sign_tokens(self) -> None:
        with pytest.raises(InvalidTokenError):
            decode_access_token(_encode(_claims(), key=settings.SECRET_KEY))

    def test_tampered_payload(self) -> None:
        header, _payload, signature = _encode(_claims()).split(".")
        forged = _encode(_claims(sub=str(uuid.uuid4())), key="x" * 64).split(".")[1]
        with pytest.raises(InvalidTokenError):
            decode_access_token(f"{header}.{forged}.{signature}")

    def test_alg_none_rejected(self) -> None:
        unsigned = jwt.encode(_claims(), key=None, algorithm="none")
        with pytest.raises(InvalidTokenError):
            decode_access_token(unsigned)

    def test_expired(self) -> None:
        past = int((timezone.now() - timedelta(minutes=20)).timestamp())
        with pytest.raises(InvalidTokenError):
            decode_access_token(_encode(_claims(iat=past, exp=past + 600)))

    def test_type_confusion_refresh_as_access_and_vice_versa(self) -> None:
        with pytest.raises(InvalidTokenError):
            decode_access_token(_encode(_claims(type="refresh")))
        with pytest.raises(InvalidTokenError):
            decode_refresh_token(_encode(_claims(type="access")))

    @pytest.mark.parametrize("missing", ["sub", "sid", "iat", "exp", "type"])
    def test_required_claims(self, missing: str) -> None:
        with pytest.raises(InvalidTokenError):
            decode_access_token(_encode(_claims(**{missing: None})))

    def test_missing_jti(self) -> None:
        with pytest.raises(InvalidTokenError):
            decode_access_token(_encode(_claims(jti=None)))

    @pytest.mark.parametrize(("claim", "value"), [("sub", "not-a-uuid"), ("sid", 42)])
    def test_malformed_identifiers(self, claim: str, value: Any) -> None:
        with pytest.raises(InvalidTokenError):
            decode_access_token(_encode(_claims(**{claim: value})))

    def test_issuer_and_audience_when_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # SimpleJWT builds its token backend once at startup from SIMPLE_JWT (environment-driven
        # DJANGO_JWT_ISSUER / DJANGO_JWT_AUDIENCE); install an equivalent configured backend here.
        from rest_framework_simplejwt.backends import TokenBackend  # noqa: PLC0415
        from rest_framework_simplejwt.tokens import Token  # noqa: PLC0415

        monkeypatch.setattr(
            Token,
            "_token_backend",
            TokenBackend("HS256", KEY, audience="aems-api", issuer="aems-test", leeway=0),
        )
        good = _encode(_claims(iss="aems-test", aud="aems-api"))
        assert decode_access_token(good)
        for bad in (
            _claims(iss="evil", aud="aems-api"),
            _claims(iss="aems-test", aud="evil"),
            _claims(),
        ):
            with pytest.raises(InvalidTokenError):
                decode_access_token(_encode(bad))
        minted = issue_access_token(user_id=str(uuid.uuid4()), session_id=str(uuid.uuid4()))
        payload = jwt.decode(minted, KEY, algorithms=["HS256"], audience="aems-api")
        assert payload["iss"] == "aems-test"


class TestPerRequestSessionValidation:
    def _get_me(self, session: Session, **headers: Any) -> Any:
        return Client().get(ME_URL, **(headers or session.auth))

    def test_valid_access_token(self, user: User, login: Any) -> None:
        session = login(user.email)
        response = self._get_me(session)
        assert response.status_code == 200
        assert response.json()["email"] == user.email
        assert "password" not in response.content.decode()

    def test_missing_token_is_401_with_challenge(self, db: Any) -> None:
        response = Client().get(ME_URL)
        assert response.status_code == 401
        assert response["WWW-Authenticate"] == 'Bearer realm="api"'
        assert response.json()["code"] == "not_authenticated"

    @pytest.mark.parametrize("header", ["Bearer", "Bearer a b", "Bearer été"])
    def test_malformed_header(self, header: str, db: Any) -> None:
        response = Client().get(ME_URL, HTTP_AUTHORIZATION=header)
        assert response.status_code == 401
        assert response.json()["code"] == "authentication_failed"

    def test_other_schemes_are_ignored(self, db: Any) -> None:
        assert Client().get(ME_URL, HTTP_AUTHORIZATION="Basic dXNlcjpwYXNz").status_code == 401

    def test_refresh_token_cannot_be_used_as_access_token(self, user: User, login: Any) -> None:
        session = login(user.email)
        response = Client().get(ME_URL, HTTP_AUTHORIZATION=f"Bearer {session.refresh_token}")
        assert response.status_code == 401

    def test_revoked_session_invalidates_access_token_immediately(
        self, user: User, login: Any
    ) -> None:
        session = login(user.email)
        AuthSession.objects.filter(user=user).update(
            revoked_at=timezone.now(), revoke_reason=RevokeReason.LOGOUT
        )
        assert self._get_me(session).status_code == 401

    def test_expired_session_rejects_unexpired_access_token(self, user: User, login: Any) -> None:
        session = login(user.email)
        AuthSession.objects.filter(user=user).update(
            expires_at=timezone.now() - timedelta(seconds=1)
        )
        assert self._get_me(session).status_code == 401

    def test_deactivation_is_immediate(self, user: User, login: Any) -> None:
        session = login(user.email)
        revoked = deactivate_user(user)

        assert revoked == 1
        assert self._get_me(session).status_code == 401
        assert AuthSession.objects.get(user=user).revoke_reason == RevokeReason.DEACTIVATED

    def test_inactive_user_rejected_even_with_active_session(self, user: User, login: Any) -> None:
        session = login(user.email)
        User.objects.filter(pk=user.pk).update(is_active=False)
        assert self._get_me(session).status_code == 401

    def test_tokens_issued_before_password_change_are_rejected(
        self, user: User, login: Any
    ) -> None:
        session = login(user.email)
        # Even if a session were somehow left active, the iat check rejects older tokens.
        User.objects.filter(pk=user.pk).update(
            password_changed_at=timezone.now() + timedelta(seconds=5)
        )
        assert self._get_me(session).status_code == 401

    def test_token_for_unknown_session(self, user: User) -> None:
        token = issue_access_token(user_id=str(user.pk), session_id=str(uuid.uuid4()))
        assert Client().get(ME_URL, HTTP_AUTHORIZATION=f"Bearer {token}").status_code == 401

    def test_token_bound_to_another_users_session(self, make_user: Any, login: Any) -> None:
        alice, bob = make_user(), make_user()
        bob_session = login(bob.email)
        sid = decode_access_token(bob_session.access_token).session_id
        forged = issue_access_token(user_id=str(alice.pk), session_id=sid)
        assert Client().get(ME_URL, HTTP_AUTHORIZATION=f"Bearer {forged}").status_code == 401
