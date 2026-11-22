"""Identity and authentication models (ADR-0004, ADR-0008)."""

import uuid
from typing import Any, ClassVar

from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import IntegrityError, models, transaction
from django.db.models.functions import Lower
from django.utils import timezone

from .normalization import normalize_email

EMAIL_UNIQUE_CONSTRAINT = "accounts_user_email_ci_uniq"


def is_email_uniqueness_violation(exc: IntegrityError) -> bool:
    cause = exc.__cause__
    diag = getattr(cause, "diag", None)
    return getattr(diag, "constraint_name", None) == EMAIL_UNIQUE_CONSTRAINT


class UserManager(BaseUserManager["User"]):
    use_in_migrations = True

    def get_by_natural_key(self, username: str | None) -> "User":
        return self.get(email=normalize_email(username))

    def _create(self, email: str, password: str | None, **extra: Any) -> "User":
        email = normalize_email(email)
        if not email:
            msg = "An email address is required."
            raise ValueError(msg)
        validate_email(email)
        user = self.model(email=email, **extra)
        if password is None:
            user.set_unusable_password()
        else:
            user.set_password(password)
        user.password_changed_at = timezone.now()
        try:
            # Savepoint: a uniqueness race leaves any outer transaction usable.
            with transaction.atomic():
                user.save(using=self._db)
        except IntegrityError as exc:
            if is_email_uniqueness_violation(exc):
                from .exceptions import EmailAlreadyRegisteredError  # noqa: PLC0415 - import cycle

                raise EmailAlreadyRegisteredError() from exc
            raise
        return user

    def create_user(self, email: str, password: str | None = None, **extra: Any) -> "User":
        extra.setdefault("is_staff", False)
        extra.setdefault("is_superuser", False)
        return self._create(email, password, **extra)

    def create_superuser(self, email: str, password: str | None = None, **extra: Any) -> "User":
        extra.setdefault("is_staff", True)
        extra.setdefault("is_superuser", True)
        if extra["is_staff"] is not True or extra["is_superuser"] is not True:
            msg = "Superusers must have is_staff=True and is_superuser=True."
            raise ValueError(msg)
        return self._create(email, password, **extra)


class User(AbstractBaseUser, PermissionsMixin):
    """Global platform identity. Organization relationships live on Membership (Batch 4)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(max_length=254)
    full_name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(
        default=False, help_text="Platform staff: may sign in to the administration site."
    )
    date_joined = models.DateTimeField(default=timezone.now, editable=False)
    password_changed_at = models.DateTimeField(null=True, blank=True, editable=False)

    objects: ClassVar[UserManager] = UserManager()

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS: ClassVar[list[str]] = ["full_name"]

    class Meta:
        constraints: ClassVar[list[Any]] = [
            models.UniqueConstraint(Lower("email"), name=EMAIL_UNIQUE_CONSTRAINT),
        ]

    def __str__(self) -> str:
        return self.email

    def clean_fields(self, exclude: Any = None) -> None:
        # Normalize before field validation so padded/mixed-case input is judged as stored.
        self.email = normalize_email(self.email)
        super().clean_fields(exclude=exclude)

    def clean(self) -> None:
        super().clean()
        self.email = normalize_email(self.email)
        if not self.email:
            raise ValidationError({"email": "An email address is required."})

    def save(self, *args: Any, **kwargs: Any) -> None:
        self.email = normalize_email(self.email)
        super().save(*args, **kwargs)


class RevokeReason(models.TextChoices):
    LOGOUT = "logout", "Logout"
    PASSWORD_CHANGED = "password_changed", "Password changed"
    PASSWORD_RESET = "password_reset", "Password reset"
    REFRESH_REUSE = "refresh_reuse", "Refresh token reuse detected"
    USER_REVOKED = "user_revoked", "Revoked by user"
    OTHER_SESSIONS_REVOKED = "other_sessions_revoked", "Other sessions revoked by user"
    DEACTIVATED = "deactivated", "Account deactivated"
    EXPIRED = "expired", "Expired"


class AuthSession(models.Model):
    """Server-side session / refresh-token family. ``id`` is the ``sid`` JWT claim."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="auth_sessions")
    refresh_jti_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField(default=timezone.now)
    last_rotated_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoke_reason = models.CharField(max_length=32, choices=RevokeReason.choices, blank=True)
    created_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=256, blank=True)

    class Meta:
        indexes: ClassVar[list[Any]] = [
            models.Index(fields=["user", "revoked_at"], name="accounts_session_user_active"),
        ]

    def __str__(self) -> str:
        return f"AuthSession {self.id}"

    def is_usable(self, now: Any = None) -> bool:
        now = now or timezone.now()
        return self.revoked_at is None and self.expires_at > now


class AuthRateLimit(models.Model):
    """Fixed-window attempt counter, keyed by an HMAC digest (no raw emails or IPs stored)."""

    scope = models.CharField(max_length=40)
    key_digest = models.CharField(max_length=64)
    window_start = models.DateTimeField()
    count = models.PositiveIntegerField(default=0)
    expires_at = models.DateTimeField(db_index=True)

    class Meta:
        constraints: ClassVar[list[Any]] = [
            models.UniqueConstraint(
                fields=["scope", "key_digest", "window_start"],
                name="accounts_ratelimit_window_uniq",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.scope}:{self.key_digest[:8]}={self.count}"


class AuthBackoff(models.Model):
    """Consecutive login failures per account digest, with an exponential temporary lockout."""

    key_digest = models.CharField(max_length=64, unique=True)
    failures = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(db_index=True)

    def __str__(self) -> str:
        return f"backoff:{self.key_digest[:8]} failures={self.failures}"


class PasswordResetDeliveryStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    DELIVERED = "delivered", "Delivered"
    FAILED = "failed", "Failed"
    EXPIRED = "expired", "Expired"
    CANCELLED = "cancelled", "Cancelled"


OUTBOX_ONE_PENDING_CONSTRAINT = "accounts_pwreset_outbox_one_pending"


class PasswordResetOutbox(models.Model):
    """Pending password-reset email for one user (ADR-0014). Not a general message queue.

    **Holds no secrets and no message content.** There is no recipient address, reset token, link
    or body column. The delivery command reads the user's *current* address and generates the
    reset token at send time, so a database read of this table reveals only that a user asked for
    a reset, and when. Rows are deleted after a bounded retention period.

    At most one ``pending`` row exists per user (partial unique constraint): repeated requests
    refresh it instead of adding rows. Requests for unknown or ineligible addresses create nothing.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="+")
    requested_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    status = models.CharField(
        max_length=16,
        choices=PasswordResetDeliveryStatus.choices,
        default=PasswordResetDeliveryStatus.PENDING,
    )
    attempts = models.PositiveSmallIntegerField(default=0)
    next_attempt_at = models.DateTimeField()
    # Lease held by the delivery command while it sends; expires so crashed work is retried.
    claim_id = models.UUIDField(null=True, blank=True)
    claimed_until = models.DateTimeField(null=True, blank=True)
    last_attempt_at = models.DateTimeField(null=True, blank=True)
    # Sanitized failure category (e.g. "timeout"), never an exception message.
    last_failure = models.CharField(max_length=32, blank=True, default="")
    delivered_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints: ClassVar[list[Any]] = [
            models.UniqueConstraint(
                fields=["user"],
                condition=models.Q(status="pending"),
                name=OUTBOX_ONE_PENDING_CONSTRAINT,
            ),
        ]
        indexes: ClassVar[list[Any]] = [
            models.Index(fields=["status", "next_attempt_at"], name="accounts_pwreset_outbox_due"),
            models.Index(fields=["completed_at"], name="accounts_pwreset_outbox_done"),
        ]

    def __str__(self) -> str:
        return f"PasswordResetOutbox {self.id} ({self.status})"
