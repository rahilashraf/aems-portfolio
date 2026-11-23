"""Server-side sessions, atomic refresh rotation and replay detection (ADR-0004, ADR-0013).

Rotation (``rotate``):

1. Validate the presented refresh token (signature, expiry, type, claims).
2. Resolve its session and lock the row (``SELECT ... FOR UPDATE``) inside ``transaction.atomic()``.
3. Reject revoked/expired sessions and inactive users.
4. Compare ``hash(jti)`` with the stored hash in constant time.
5. Match: issue a new access + refresh pair and persist the new hash (compare-and-swap; only one
   concurrent request can win because the others wait on the row lock and then see a new hash).
6. Mismatch (an already-rotated token was replayed): revoke the session (the whole token family).

The function **never raises inside the atomic block** on the replay path. It returns an outcome; the
revocation commits when the block exits, and only then is the security event recorded and a generic
401 produced by the view. Raising inside the block would roll the revocation back.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from hmac import compare_digest
from typing import Any

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.audit import services as audit
from apps.core.security_events import log_security_event

from .models import AuthSession, RevokeReason, User
from .tokens import (
    InvalidTokenError,
    decode_access_token,
    decode_refresh_token,
    hash_jti,
    issue_access_token,
    issue_refresh_token,
)

USER_AGENT_MAX_LENGTH = 256


@dataclass(frozen=True)
class IssuedTokens:
    access_token: str
    refresh_token: str
    session: AuthSession
    refresh_expires_at: datetime


def absolute_session_lifetime() -> timedelta:
    return timedelta(seconds=int(settings.AUTH_SESSION_ABSOLUTE_LIFETIME_SECONDS))


def create_session(
    user: User, *, client_ip: str | None, user_agent: str = "", now: datetime | None = None
) -> IssuedTokens:
    """Create a session and its first token pair. Call inside the caller's transaction."""
    now = now or timezone.now()
    session = AuthSession(
        user=user,
        created_at=now,
        last_rotated_at=now,
        expires_at=now + absolute_session_lifetime(),
        created_ip=client_ip,
        user_agent=(user_agent or "")[:USER_AGENT_MAX_LENGTH],
        refresh_jti_hash="",
    )
    tokens = _issue_pair(session, now)
    session.save()
    return tokens


def _issue_pair(session: AuthSession, now: datetime) -> IssuedTokens:
    user_id, session_id = str(session.user_id), str(session.id)
    refresh, jti = issue_refresh_token(
        user_id=user_id, session_id=session_id, session_expires_at=session.expires_at, now=now
    )
    session.refresh_jti_hash = hash_jti(jti)
    session.last_rotated_at = now
    access = issue_access_token(user_id=user_id, session_id=session_id, now=now)
    refresh_lifetime = min(
        timedelta(seconds=int(settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds())),
        session.expires_at - now,
    )
    return IssuedTokens(access, refresh, session, now + refresh_lifetime)


class RotationOutcome(Enum):
    ROTATED = "rotated"
    INVALID = "invalid"
    REUSE_DETECTED = "reuse_detected"


@dataclass(frozen=True)
class RotationResult:
    outcome: RotationOutcome
    tokens: IssuedTokens | None = None
    session_id: str | None = None
    user_id: str | None = None


def rotate(raw_refresh_token: str, *, client_ip: str | None = None) -> RotationResult:
    try:
        claims = decode_refresh_token(raw_refresh_token)
    except InvalidTokenError:
        audit.record_security_event(
            "auth.refresh.rejected", client_ip=client_ip, metadata={"reason": "invalid_token"}
        )
        return RotationResult(RotationOutcome.INVALID)

    now = timezone.now()
    with transaction.atomic():
        session = (
            AuthSession.objects.select_for_update()
            .select_related("user")
            .filter(id=claims.session_id, user_id=claims.user_id)
            .first()
        )
        if session is None or not session.is_usable(now) or not session.user.is_active:
            result = RotationResult(RotationOutcome.INVALID, session_id=claims.session_id)
        elif not compare_digest(session.refresh_jti_hash, hash_jti(claims.jti)):
            session.revoked_at = now
            session.revoke_reason = RevokeReason.REFRESH_REUSE
            session.save(update_fields=["revoked_at", "revoke_reason"])
            # Same transaction as the revocation: both commit together (nothing raises here).
            audit.record(
                "auth.refresh.reuse_detected",
                outcome="failure",
                actor=session.user,
                target_type="session",
                target_id=session.id,
                client_ip=client_ip,
                metadata={"session_id": session.id, "reason": RevokeReason.REFRESH_REUSE},
            )
            result = RotationResult(
                RotationOutcome.REUSE_DETECTED,
                session_id=str(session.id),
                user_id=str(session.user_id),
            )
        else:
            tokens = _issue_pair(session, now)
            session.save(update_fields=["refresh_jti_hash", "last_rotated_at"])
            result = RotationResult(
                RotationOutcome.ROTATED,
                tokens=tokens,
                session_id=str(session.id),
                user_id=str(session.user_id),
            )
    # The transaction has committed: a replay revocation and its audit record are durable before
    # the caller reports anything.
    if result.outcome is RotationOutcome.INVALID:
        audit.record_security_event(
            "auth.refresh.rejected",
            client_ip=client_ip,
            metadata={"session_id": result.session_id, "reason": "session_unusable"},
        )
    elif result.outcome is RotationOutcome.ROTATED:
        # Operational log only: rotation happens every few minutes per session and changes no
        # account state, so it is not an audit record (ADR-0016).
        log_security_event(
            "auth.refresh.rotated",
            outcome="success",
            user_id=result.user_id,
            session_id=result.session_id,
            client_ip=client_ip,
        )
    return result


@dataclass(frozen=True)
class AccessContext:
    user: User
    session: AuthSession


def authenticate_access_token(raw: str) -> AccessContext:
    """Validate an access token *and* its server-side session/user state (every request).

    Revoked or expired sessions, inactive users and tokens issued before the last password change
    are rejected immediately, regardless of the token's own expiry.
    """
    claims = decode_access_token(raw)
    session = (
        AuthSession.objects.select_related("user")
        .filter(id=claims.session_id, user_id=claims.user_id)
        .first()
    )
    if session is None or not session.is_usable():
        raise InvalidTokenError
    user = session.user
    if not user.is_active:
        raise InvalidTokenError
    changed = user.password_changed_at
    if changed is not None and claims.issued_at < changed.replace(microsecond=0):
        raise InvalidTokenError
    return AccessContext(user=user, session=session)


def session_for_refresh_token(raw: str, *, client_ip: str | None = None) -> AuthSession | None:
    """The session a *valid* refresh token belongs to, or ``None``.

    The session is resolved by **both** signed claims: ``sid`` and ``sub`` (the session owner). A
    session id alone never identifies a session to act on. A signature-valid token whose ``sid``
    names another user's session can only arise from a leaked signing key or a defect, so it is
    reported as a security event and treated as unknown. Invalid or expired tokens return ``None``.
    """
    try:
        claims = decode_refresh_token(raw)
    except InvalidTokenError:
        return None
    session = AuthSession.objects.filter(id=claims.session_id, user_id=claims.user_id).first()
    if session is None and AuthSession.objects.filter(id=claims.session_id).exists():
        audit.record_security_event(
            "auth.session.owner_mismatch",
            target_type="session",
            target_id=claims.session_id,
            client_ip=client_ip,
            metadata={"session_id": claims.session_id, "token_user_id": claims.user_id},
        )
    return session


def revoke_session(
    session: AuthSession,
    reason: str,
    *,
    client_ip: str | None = None,
    actor: User | None = None,
) -> bool:
    """Revoke one session (idempotent). Returns True if it was active.

    ``actor`` defaults to the session's owner (logout, own-session revocation); pass the
    administrator when one revokes someone else's session.
    """
    with transaction.atomic():
        updated = AuthSession.objects.filter(id=session.id, revoked_at__isnull=True).update(
            revoked_at=timezone.now(), revoke_reason=reason
        )
        if updated:
            audit.record(
                "auth.session.revoked",
                actor=actor or session.user,
                target_type="session",
                target_id=session.id,
                client_ip=client_ip,
                metadata={"session_id": session.id, "reason": reason},
            )
    return bool(updated)


def revoke_user_sessions(
    user: User,
    reason: str,
    *,
    except_session_id: Any = None,
    client_ip: str | None = None,
    actor: User | None = None,
) -> int:
    """Revoke every active session of a user (optionally keeping one).

    Must run inside the caller's transaction: the revocation and its audit record commit together.
    """
    queryset = AuthSession.objects.filter(user_id=user.pk, revoked_at__isnull=True)
    if except_session_id is not None:
        queryset = queryset.exclude(id=except_session_id)
    count = queryset.update(revoked_at=timezone.now(), revoke_reason=reason)
    if count:
        audit.record(
            "auth.sessions.revoked",
            actor=actor,
            target_type="user",
            target_id=user.pk,
            client_ip=client_ip,
            metadata={"reason": reason, "count": count},
        )
    return count
