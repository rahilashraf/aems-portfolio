"""JWT issuing/validation (SimpleJWT primitives) and password-reset tokens (ADR-0004).

Access token claims: ``sub`` (user id), ``sid`` (AuthSession id), ``jti``, ``iat``, ``exp``,
``type="access"``; optional ``iss``/``aud`` when configured. Refresh tokens carry the same claims
with ``type="refresh"``. Tokens are HS256-signed with ``SIMPLE_JWT["SIGNING_KEY"]`` (a dedicated
key, never ``SECRET_KEY``). Validation checks signature, expiry, type, issuer/audience (when
configured) and the presence of every required claim; any failure raises
:class:`InvalidTokenError` without details.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils import timezone
from django.utils.crypto import salted_hmac
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken, Token

REQUIRED_CLAIMS = ("sub", "sid", "jti", "iat", "exp", "type")


class InvalidTokenError(Exception):
    """Raised for any invalid token; carries no detail by design."""


@dataclass(frozen=True)
class TokenClaims:
    user_id: str
    session_id: str
    jti: str
    issued_at: datetime
    expires_at: datetime


def hash_jti(jti: str) -> str:
    """Keyed hash of a refresh-token jti (only hashes are stored server-side)."""
    return salted_hmac("aems.accounts.refresh-jti", jti, algorithm="sha256").hexdigest()


def _stamp(
    token: Token, *, user_id: str, session_id: str, now: datetime, lifetime: timedelta
) -> None:
    token.set_iat(at_time=now)
    token.set_exp(from_time=now, lifetime=lifetime)
    token["sub"] = user_id
    token["sid"] = session_id
    token["jti"] = uuid.uuid4().hex


def issue_access_token(*, user_id: str, session_id: str, now: datetime | None = None) -> str:
    now = now or timezone.now()
    token = AccessToken()
    _stamp(token, user_id=user_id, session_id=session_id, now=now, lifetime=AccessToken.lifetime)
    return str(token)


def issue_refresh_token(
    *, user_id: str, session_id: str, session_expires_at: datetime, now: datetime | None = None
) -> tuple[str, str]:
    """Return ``(token, jti)``. Expiry is capped at the session's absolute lifetime."""
    now = now or timezone.now()
    lifetime = min(RefreshToken.lifetime, session_expires_at - now)
    token = RefreshToken()
    _stamp(token, user_id=user_id, session_id=session_id, now=now, lifetime=lifetime)
    return str(token), str(token["jti"])


def _decode(raw: str, token_class: type[Token]) -> TokenClaims:
    if not raw or not isinstance(raw, str):
        raise InvalidTokenError
    try:
        # Verifies signature, exp, iss/aud (if configured) and type. (Stubs type the arg as Token.)
        token = token_class(raw)  # type: ignore[arg-type]
    except TokenError as exc:
        raise InvalidTokenError from exc
    payload: dict[str, Any] = token.payload
    if any(claim not in payload for claim in REQUIRED_CLAIMS):
        raise InvalidTokenError
    try:
        return TokenClaims(
            user_id=str(uuid.UUID(str(payload["sub"]))),
            session_id=str(uuid.UUID(str(payload["sid"]))),
            jti=str(payload["jti"]),
            issued_at=datetime.fromtimestamp(int(payload["iat"]), tz=UTC),
            expires_at=datetime.fromtimestamp(int(payload["exp"]), tz=UTC),
        )
    except (TypeError, ValueError) as exc:
        raise InvalidTokenError from exc


def decode_access_token(raw: str) -> TokenClaims:
    return _decode(raw, AccessToken)


def decode_refresh_token(raw: str) -> TokenClaims:
    return _decode(raw, RefreshToken)


class PasswordResetTokens(PasswordResetTokenGenerator):
    """Django's reset-token generator, additionally bound to ``password_changed_at``.

    Tokens expire after ``PASSWORD_RESET_TIMEOUT`` and become invalid as soon as the password (or
    its change timestamp, or ``last_login``) changes, which makes them single-use.
    """

    key_salt = "aems.accounts.password-reset"

    def _make_hash_value(self, user: Any, timestamp: int) -> str:
        changed = user.password_changed_at.isoformat() if user.password_changed_at else ""
        return f"{super()._make_hash_value(user, timestamp)}{changed}{user.is_active}"


password_reset_tokens = PasswordResetTokens()
