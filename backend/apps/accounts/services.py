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

from apps.core.api.exceptions import DomainError
from apps.core.security_events import record_after_commit, record_security_event

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


def _raise_if_limited(result: ratelimit.RateLimitResult | None, **event: Any) -> None:
    if result is not None:
        record_security_event("auth.rate_limited", outcome="failure", **event)
        raise RateLimitedError(wait=result.retry_after)


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
        record_security_event(
            "auth.login.locked",
            outcome="failure",
            client_ip=client_ip,
            subject_digest=account_digest,
        )
        raise RateLimitedError(wait=locked_for)

    # Unknown accounts, wrong passwords and inactive users take the same path and produce the same
    # response; Django's backend runs the password hasher for unknown users too (comparable timing).
    user = authenticate(request, email=normalized, password=password)
    if not isinstance(user, User):
        lock_seconds = ratelimit.register_failure(account_digest)
        record_security_event(
            "auth.login.failed",
            outcome="failure",
            client_ip=client_ip,
            subject_digest=account_digest,
            locked_for_seconds=lock_seconds,
        )
        raise InvalidCredentialsError()

    ratelimit.reset_failures(account_digest)
    with transaction.atomic():
        tokens = create_session(user, client_ip=client_ip, user_agent=user_agent)
        User.objects.filter(pk=user.pk).update(last_login=timezone.now())
        record_after_commit(
            "auth.login.succeeded",
            user_id=user.pk,
            session_id=tokens.session.id,
            client_ip=client_ip,
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
        user_id=user.pk,
        client_ip=client_ip,
    )
    if not user.check_password(current_password):
        record_security_event(
            "auth.password_change.failed", outcome="failure", user_id=user.pk, client_ip=client_ip
        )
        raise exceptions.ValidationError(
            {"current_password": ["The current password is incorrect."]}
        )
    _validate_new_password(new_password, user)

    with transaction.atomic():
        locked = User.objects.select_for_update().get(pk=user.pk)
        locked.set_password(new_password)
        locked.password_changed_at = timezone.now()
        locked.save(update_fields=["password", "password_changed_at"])
        revoke_user_sessions(locked, RevokeReason.PASSWORD_CHANGED, client_ip=client_ip)
        tokens = create_session(locked, client_ip=client_ip, user_agent=user_agent)
        record_after_commit(
            "auth.password.changed",
            user_id=locked.pk,
            session_id=tokens.session.id,
            client_ip=client_ip,
            previous_session_id=current_session.id,
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
    except DatabaseError as exc:
        record_security_event(
            "auth.password_reset.enqueue_failed",
            outcome="failure",
            client_ip=client_ip,
            subject_digest=account_digest,
            error_type=type(exc).__name__,
        )
        return
    record_security_event(
        "auth.password_reset.requested",
        outcome="success",
        user_id=user_id,
        client_ip=client_ip,
        subject_digest=account_digest,
        queued=user_id is not None,
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
        record_security_event("auth.password_reset.failed", outcome="failure", client_ip=client_ip)
        raise InvalidResetTokenError()
    _validate_new_password(new_password, user)

    with transaction.atomic():
        locked = User.objects.select_for_update().get(pk=user.pk)
        if not password_reset_tokens.check_token(locked, token):  # raced with another reset
            raise InvalidResetTokenError()
        locked.set_password(new_password)
        locked.password_changed_at = timezone.now()
        locked.save(update_fields=["password", "password_changed_at"])
        revoke_user_sessions(locked, RevokeReason.PASSWORD_RESET, client_ip=client_ip)
        record_after_commit("auth.password_reset.completed", user_id=locked.pk, client_ip=client_ip)
    ratelimit.reset_failures(ratelimit.digest("email", locked.email))


def _user_from_uid(uid: str) -> User | None:
    try:
        pk = force_str(urlsafe_base64_decode(uid))
        return User.objects.filter(pk=pk).first()
    except (TypeError, ValueError, OverflowError, ValidationError):
        return None


# --------------------------------------------------------------------------- deactivation
def deactivate_user(user: User, *, actor: User | None = None) -> int:
    """Deactivate an account and revoke all of its sessions in one transaction.

    Batch 6 requirement: before ``is_active`` is cleared, lock every active organization in which
    the
    user is an active Owner (ascending id) and refuse if any would be left without another active
    Owner (plan §6.3). Until organizations exist there is no owner invariant to enforce.
    """
    with transaction.atomic():
        locked = User.objects.select_for_update().get(pk=user.pk)
        if locked.is_active:
            locked.is_active = False
            locked.save(update_fields=["is_active"])
        revoked = revoke_user_sessions(locked, RevokeReason.DEACTIVATED)
        record_after_commit(
            "auth.account.deactivated",
            user_id=locked.pk,
            actor_id=getattr(actor, "pk", None),
            sessions_revoked=revoked,
        )
    return revoked
