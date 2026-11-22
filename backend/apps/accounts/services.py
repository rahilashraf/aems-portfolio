"""Account services: login, password change/reset and deactivation (ADR-0004).

Views stay thin; every rule (rate limits, backoff, enumeration resistance, session revocation,
transactions, security events) lives here.
"""

import smtplib
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.contrib.auth import authenticate, password_validation
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import exceptions

from apps.core.api.exceptions import DomainError
from apps.core.security_events import record_after_commit, record_security_event

from . import ratelimit
from .models import AuthSession, RevokeReason, User
from .normalization import normalize_email
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
# Failures of the mail transport we expect in operation: SMTP protocol/auth/recipient errors and
# network errors (refused, reset, DNS, timeouts — ``TimeoutError`` and ``socket.gaierror`` are
# ``OSError`` subclasses).
EXPECTED_MAIL_ERRORS: tuple[type[BaseException], ...] = (smtplib.SMTPException, OSError)


def request_password_reset(*, email: str, client_ip: str | None) -> None:
    """Send a reset link if an active account exists. The caller always answers 202.

    Enumeration resistance:

    - Rate limits apply per IP and per submitted address whether or not the account exists, so 429
      responses reveal nothing about existence.
    - **Delivery failures never change the response.** Any exception raised while sending is
      caught, so a known account whose email cannot be sent gets the same 202, body and headers as
      an unknown one. The failure is reported as ``auth.password_reset.delivery_failed`` with
      identifiers only: the user id, the subject digest and the exception *class*. The exception
      message is deliberately not logged, because transport errors such as
      ``SMTPRecipientsRefused`` embed the recipient address. The reset token is never logged.
    - Acceptance does not guarantee delivery. The request is not retried; the user can request a
      new link (within the rate limits).

    Timing: this is **not** constant time. For a known account the request also generates a reset
    token and waits for the mail transport (an SMTP round trip, bounded by ``EMAIL_TIMEOUT``),
    which an unknown account does not, so response time can distinguish the two. Closing that
    side channel requires moving delivery out of the request (an outbox/worker), which is out of
    scope for Batch 3; the per-IP and per-address rate limits bound how fast it can be probed.
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
    user = User.objects.filter(email=normalized, is_active=True).first()
    if user is None or not user.has_usable_password():
        record_security_event(
            "auth.password_reset.requested",
            outcome="success",
            client_ip=client_ip,
            subject_digest=account_digest,
            account_found=False,
        )
        return

    record_security_event(
        "auth.password_reset.requested",
        outcome="success",
        user_id=user.pk,
        client_ip=client_ip,
        subject_digest=account_digest,
        account_found=True,
    )
    try:
        _send_password_reset_email(user)
    except Exception as exc:
        # Deliberately broad: *any* failure here would otherwise turn into a 500 for existing
        # accounts only and reveal that the account exists. Unexpected errors are flagged so they
        # stand out from routine transport failures.
        record_security_event(
            "auth.password_reset.delivery_failed",
            outcome="failure",
            user_id=user.pk,
            client_ip=client_ip,
            subject_digest=account_digest,
            error_type=type(exc).__name__,
            expected=isinstance(exc, EXPECTED_MAIL_ERRORS),
        )


def _send_password_reset_email(user: User) -> None:
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = password_reset_tokens.make_token(user)
    # The token travels in the URL fragment, which browsers never send to servers or in Referer.
    link = settings.PASSWORD_RESET_URL_TEMPLATE.format(uid=uid, token=token)
    send_mail(
        subject="Reset your AEMS password",
        message=(
            f"Hello {user.full_name},\n\n"
            "A password reset was requested for your AEMS account. Use the link below to choose a "
            "new password. The link expires and can only be used once.\n\n"
            f"{link}\n\n"
            "If you did not request this, you can ignore this email; your password is unchanged.\n"
        ),
        from_email=None,
        recipient_list=[user.email],
        fail_silently=False,
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
