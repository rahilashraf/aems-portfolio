"""Account services: login, password change/reset and deactivation (ADR-0004).

Views stay thin; every rule (rate limits, backoff, enumeration resistance, session revocation,
transactions, security events) lives here.
"""

from dataclasses import dataclass
from typing import Any

from django.contrib.auth import authenticate, password_validation
from django.core.exceptions import ValidationError
from django.db import DatabaseError, transaction
from django.utils import timezone
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import exceptions

from apps.audit import services as audit
from apps.core.api.exceptions import DomainError
from apps.core.security_events import log_security_event
from apps.rbac import services as rbac

from . import ratelimit
from .models import AuthSession, RevokeReason, User
from .normalization import normalize_email
from .outbox import enqueue_password_reset
from .sessions import IssuedTokens, create_session, revoke_user_sessions
from .tokens import password_reset_tokens


# --------------------------------------------------------------------------- domain errors
class InvalidCredentialsError(DomainError, exceptions.AuthenticationFailed):
    status_code = 401
    default_detail = "Invalid email or password."
    default_code = "invalid_credentials"


class RateLimitedError(exceptions.Throttled):
    """429 with Retry-After; the generic throttled message is used (ADR-0009)."""


class InvalidResetTokenError(DomainError):
    status_code = 400
    default_detail = "The password reset link is invalid or has expired."
    default_code = "invalid_reset_token"


def _raise_if_limited(
    result: ratelimit.RateLimitResult | None,
    *,
    scope: str,
    client_ip: str | None = None,
    subject_digest: str | None = None,
    actor: User | None = None,
) -> None:
    if result is not None:
        record_rate_limited(
            result,
            scope=scope,
            client_ip=client_ip,
            subject_digest=subject_digest,
            actor=actor,
        )
        raise RateLimitedError(wait=result.retry_after)


def record_rate_limited(
    result: ratelimit.RateLimitResult,
    *,
    scope: str,
    client_ip: str | None,
    subject_digest: str | None = None,
    actor: User | None = None,
    action: str = "auth.rate_limited",
) -> None:
    """Durable ``action`` event for the first refusal of a window, a log line afterwards.

    Every refused request used to write an audit row, so an unauthenticated flood could grow the
    append-only table without bound (AEMS-025). The first refusal per scope, key and window is
    still recorded durably; later ones are visible in the structured log under the same name.
    Used by the API limiter (``auth.rate_limited``) and the admin sign-in
    (``auth.admin_login.rate_limited``).
    """
    if result.first_denial:
        audit.record_security_event(
            action,
            actor=actor,
            client_ip=client_ip,
            metadata={"scope": scope, "subject_digest": subject_digest},
        )
        return
    log_security_event(
        action,
        outcome="failure",
        user_id=actor.pk if actor is not None else None,
        client_ip=client_ip,
        subject_digest=subject_digest,
        scope=scope,
        repeated=True,
    )


def check_refresh_rate_limit(client_ip: str | None) -> None:
    _raise_if_limited(
        ratelimit.check_all([("refresh_ip", ratelimit.digest("ip", client_ip or "unknown"))]),
        scope="refresh",
        client_ip=client_ip,
    )


# --------------------------------------------------------------------------- login
@dataclass(frozen=True)
class LoginResult:
    user: User
    tokens: IssuedTokens


def login(
    *, request: Any, email: str, password: str, client_ip: str | None, user_agent: str
) -> LoginResult:
    normalized = normalize_email(email)
    account_digest = ratelimit.digest("email", normalized)
    ip_digest = ratelimit.digest("ip", client_ip or "unknown")

    _raise_if_limited(
        ratelimit.check_all(
            [
                ("login_ip", ip_digest),
                ("login_account", account_digest),
                ("login_ip_account", ratelimit.digest("ip_email", f"{client_ip}|{normalized}")),
            ]
        ),
        scope="login",
        client_ip=client_ip,
        subject_digest=account_digest,
    )
    locked_for = ratelimit.backoff_remaining(account_digest)
    if locked_for:
        audit.record_security_event(
            "auth.login.locked", client_ip=client_ip, metadata={"subject_digest": account_digest}
        )
        raise RateLimitedError(wait=locked_for)

    # Unknown accounts, wrong passwords and inactive users take the same path and produce the same
    # response; Django's backend runs the password hasher for unknown users too (comparable timing).
    user = authenticate(request, email=normalized, password=password)
    if not isinstance(user, User):
        lock_seconds = ratelimit.register_failure(account_digest)
        audit.record_security_event(
            "auth.login.failed",
            client_ip=client_ip,
            metadata={"subject_digest": account_digest, "locked_for_seconds": lock_seconds},
        )
        raise InvalidCredentialsError()

    ratelimit.reset_failures(account_digest)
    with transaction.atomic():
        tokens = create_session(user, client_ip=client_ip, user_agent=user_agent)
        User.objects.filter(pk=user.pk).update(last_login=timezone.now())
        audit.record(
            "auth.login.succeeded",
            actor=user,
            target_type="session",
            target_id=tokens.session.id,
            client_ip=client_ip,
            metadata={"session_id": tokens.session.id},
        )
    return LoginResult(user=user, tokens=tokens)


# --------------------------------------------------------------------------- password change
def change_password(
    *,
    user: User,
    current_session: AuthSession,
    current_password: str,
    new_password: str,
    client_ip: str | None,
    user_agent: str,
) -> IssuedTokens:
    """Verify, change, revoke **all** sessions and issue a fresh session for the caller."""
    _raise_if_limited(
        ratelimit.check_all([("password_change_user", ratelimit.digest("user", str(user.pk)))]),
        scope="password_change",
        actor=user,
        client_ip=client_ip,
    )
    if not user.check_password(current_password):
        audit.record_security_event(
            "auth.password_change.failed",
            actor=user,
            target_type="user",
            target_id=user.pk,
            client_ip=client_ip,
        )
        raise exceptions.ValidationError(
            {"current_password": ["The current password is incorrect."]}
        )
    _validate_new_password(new_password, user)

    with transaction.atomic():
        locked = User.objects.select_for_update(no_key=True).get(pk=user.pk)
        locked.set_password(new_password)
        locked.password_changed_at = timezone.now()
        locked.save(update_fields=["password", "password_changed_at"])
        revoke_user_sessions(
            locked, RevokeReason.PASSWORD_CHANGED, client_ip=client_ip, actor=locked
        )
        tokens = create_session(locked, client_ip=client_ip, user_agent=user_agent)
        audit.record(
            "auth.password.changed",
            actor=locked,
            target_type="user",
            target_id=locked.pk,
            changes={"password": (None, None)},
            client_ip=client_ip,
            metadata={"session_id": tokens.session.id, "previous_session_id": current_session.id},
        )
    return tokens


def _validate_new_password(password: str, user: User | None) -> None:
    try:
        password_validation.validate_password(password, user)
    except ValidationError as exc:
        raise exceptions.ValidationError({"new_password": list(exc.messages)}) from exc


# --------------------------------------------------------------------------- password reset
def request_password_reset(*, email: str, client_ip: str | None) -> None:
    """Queue a reset email if an eligible account exists. The caller always answers 202.

    Enumeration resistance (ADR-0014):

    - **No SMTP in the request.** The request only enqueues; ``deliver_password_reset_emails``
      sends later. Mail-server latency and failures therefore cannot show in the response.
    - **Same work whatever the address.** After the rate limits (also applied to every address),
      one SQL statement both looks up the account and conditionally inserts the outbox row. Known
      and unknown addresses run the same statement; only the server-side event differs.
    - **No row for unknown addresses**, and at most one pending row per user, so requests cannot
      grow the outbox without bound or queue mail to arbitrary addresses.
    - **Enqueue failures do not change the response.** A database error from the enqueue
      statement is recorded as ``auth.password_reset.enqueue_failed`` (no address) and the
      request still answers 202.

    Not constant time: the lookup, a conditional insert and the database itself can still differ
    by small amounts. A 202 means "accepted", not "delivered".
    """
    normalized = normalize_email(email)
    account_digest = ratelimit.digest("email", normalized)
    _raise_if_limited(
        ratelimit.check_all(
            [
                ("password_reset_ip", ratelimit.digest("ip", client_ip or "unknown")),
                ("password_reset_account", account_digest),
            ]
        ),
        scope="password_reset",
        client_ip=client_ip,
        subject_digest=account_digest,
    )
    try:
        with transaction.atomic():
            user_id = enqueue_password_reset(normalized)
            # Same transaction as the enqueue: no queued email without its audit record.
            audit.record(
                "auth.password_reset.requested",
                target_type="user" if user_id else "",
                target_id=user_id or "",
                client_ip=client_ip,
                metadata={"subject_digest": account_digest, "queued": user_id is not None},
            )
    except DatabaseError as exc:
        # The transaction has rolled back; record the failure in its own transaction.
        audit.record_security_event(
            "auth.password_reset.enqueue_failed",
            client_ip=client_ip,
            metadata={"subject_digest": account_digest, "error_type": type(exc).__name__},
        )


def confirm_password_reset(
    *, uid: str, token: str, new_password: str, client_ip: str | None
) -> None:
    _raise_if_limited(
        ratelimit.check_all(
            [("password_reset_confirm_ip", ratelimit.digest("ip", client_ip or "unknown"))]
        ),
        scope="password_reset_confirm",
        client_ip=client_ip,
    )
    user = _user_from_uid(uid)
    if user is None or not user.is_active or not password_reset_tokens.check_token(user, token):
        audit.record_security_event("auth.password_reset.failed", client_ip=client_ip)
        raise InvalidResetTokenError()
    _validate_new_password(new_password, user)

    with transaction.atomic():
        locked = User.objects.select_for_update(no_key=True).get(pk=user.pk)
        if not password_reset_tokens.check_token(locked, token):  # raced with another reset
            raise InvalidResetTokenError()
        locked.set_password(new_password)
        locked.password_changed_at = timezone.now()
        locked.save(update_fields=["password", "password_changed_at"])
        revoke_user_sessions(locked, RevokeReason.PASSWORD_RESET, client_ip=client_ip, actor=locked)
        audit.record(
            "auth.password_reset.completed",
            actor=locked,
            target_type="user",
            target_id=locked.pk,
            changes={"password": (None, None)},
            client_ip=client_ip,
        )
    ratelimit.reset_failures(ratelimit.digest("email", locked.email))


def _user_from_uid(uid: str) -> User | None:
    try:
        pk = force_str(urlsafe_base64_decode(uid))
        return User.objects.filter(pk=pk).first()
    except (TypeError, ValueError, OverflowError, ValidationError):
        return None


# --------------------------------------------------------------------------- profile
#: Fields a user may change on their own profile (``PATCH /auth/me/``).
PROFILE_FIELDS = ("full_name",)


def update_profile(user: User, changes: dict[str, Any], *, client_ip: str | None = None) -> User:
    """Apply a self-service profile change and record it in the same transaction.

    Only :data:`PROFILE_FIELDS` are applied. The user row is locked so the recorded ``from`` value
    is the one actually replaced. A submission that changes nothing writes nothing and records
    nothing. If the audit insert fails, the change rolls back (ADR-0016).
    """
    unknown = set(changes) - set(PROFILE_FIELDS)
    if unknown:
        msg = f"Profile fields {sorted(unknown)} cannot be changed here."
        raise ValueError(msg)
    with transaction.atomic():
        locked = User.objects.select_for_update(no_key=True).get(pk=user.pk)
        diff = {
            name: (getattr(locked, name), value)
            for name, value in changes.items()
            if getattr(locked, name) != value
        }
        if diff:
            for name, (_before, after) in diff.items():
                setattr(locked, name, after)
            locked.save(update_fields=list(diff))
            audit.record(
                "auth.account.profile_updated",
                actor=locked,
                target_type="user",
                target_id=locked.pk,
                changes=diff,
                client_ip=client_ip,
            )
    return locked


# --------------------------------------------------------------------------- deactivation
def deactivate_user(user: User, *, actor: User | None = None) -> int:
    """Deactivate an account and revoke all of its sessions in one transaction (plan §6.3).

    Lock order: the user row, then every organization in which the user has a membership
    (ascending id, :func:`apps.rbac.services.assert_deactivation_keeps_owners`). If the user is
    the last active Owner of any active organization, ``LastOwnerError`` (409) lists every
    blocking organization and nothing changes anywhere. Platform administrators get no bypass.
    """
    with transaction.atomic():
        locked = User.objects.select_for_update(no_key=True).get(pk=user.pk)
        was_active = locked.is_active
        if was_active:
            rbac.assert_deactivation_keeps_owners(locked)
            locked.is_active = False
            locked.save(update_fields=["is_active"])
        revoked = revoke_user_sessions(locked, RevokeReason.DEACTIVATED, actor=actor)
        audit.record(
            "auth.account.deactivated",
            actor=actor,
            target_type="user",
            target_id=locked.pk,
            changes={"is_active": (True, False)} if was_active else None,
            metadata={"sessions_revoked": revoked},
        )
    return revoked
