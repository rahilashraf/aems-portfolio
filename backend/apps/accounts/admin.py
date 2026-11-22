"""Platform administration for accounts (staff only).

- The admin login is protected by the same rate limits and account backoff as the API login.
- Password hashes are never displayed: the change form has no password field; passwords are set via
  the dedicated admin password-change view, which also revokes every session of that user.
- Only superusers may change ``is_staff``, ``is_superuser``, groups or permissions, so staff cannot
  escalate themselves or others.
- Deactivating an account (clearing ``is_active``) goes through ``services.deactivate_user``, which
  revokes all of its sessions. Batch 6 adds the last-active-Owner check to that service; there is
  deliberately no other deactivation path.
"""

from typing import Any

from django import forms
from django.contrib import admin, messages
from django.contrib.admin.forms import AdminAuthenticationForm
from django.contrib.auth import password_validation
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.contrib.auth.forms import AdminPasswordChangeForm
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import QuerySet
from django.http import HttpRequest
from django.utils import timezone

from apps.core.net import client_ip
from apps.core.security_events import record_after_commit, record_security_event

from . import ratelimit
from .models import AuthSession, RevokeReason, User
from .normalization import normalize_email
from .services import deactivate_user
from .sessions import revoke_session, revoke_user_sessions

PRIVILEGED_FIELDS = ("is_staff", "is_superuser", "groups", "user_permissions")


class RateLimitedAdminAuthenticationForm(AdminAuthenticationForm):
    error_messages = {
        **AdminAuthenticationForm.error_messages,
        "rate_limited": "Too many sign-in attempts. Please try again later.",
    }

    def clean(self) -> dict[str, Any]:
        email = normalize_email(self.cleaned_data.get("username"))
        ip = client_ip(self.request) if self.request is not None else None
        account = ratelimit.digest("email", email)
        limited = ratelimit.check_all(
            [
                ("login_ip", ratelimit.digest("ip", ip or "unknown")),
                ("login_account", account),
                ("login_ip_account", ratelimit.digest("ip_email", f"{ip}|{email}")),
            ]
        )
        if limited is not None or ratelimit.backoff_remaining(account):
            record_security_event(
                "auth.admin_login.rate_limited",
                outcome="failure",
                client_ip=ip,
                subject_digest=account,
            )
            raise ValidationError(self.error_messages["rate_limited"], code="rate_limited")
        try:
            cleaned = super().clean()
        except ValidationError:
            ratelimit.register_failure(account)
            record_security_event(
                "auth.admin_login.failed", outcome="failure", client_ip=ip, subject_digest=account
            )
            raise
        ratelimit.reset_failures(account)
        record_security_event(
            "auth.admin_login.succeeded",
            outcome="success",
            user_id=self.get_user().pk,
            client_ip=ip,
        )
        return cleaned


admin.site.login_form = RateLimitedAdminAuthenticationForm
admin.site.site_header = "AEMS administration"
admin.site.site_title = "AEMS administration"


class UserCreationForm(forms.ModelForm):  # type: ignore[type-arg]
    password1 = forms.CharField(label="Password", strip=False, widget=forms.PasswordInput)
    password2 = forms.CharField(
        label="Password confirmation", strip=False, widget=forms.PasswordInput
    )

    class Meta:
        model = User
        fields = ("email", "full_name")

    def clean_email(self) -> str:
        email = normalize_email(self.cleaned_data.get("email"))
        if User.objects.filter(email=email).exists():
            raise ValidationError("An account with this email address already exists.")
        return email

    def clean(self) -> dict[str, Any]:
        cleaned = super().clean() or {}
        p1, p2 = cleaned.get("password1"), cleaned.get("password2")
        if p1 and p2 and p1 != p2:
            self.add_error("password2", "The two password fields didn't match.")
        elif p1:
            try:
                password_validation.validate_password(p1, self.instance)
            except ValidationError as exc:
                self.add_error("password1", exc)
        return cleaned

    def save(self, commit: bool = True) -> User:
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        user.password_changed_at = timezone.now()
        if commit:
            user.save()
        return user  # type: ignore[no-any-return]


class UserChangeForm(forms.ModelForm):  # type: ignore[type-arg]
    """No password field: the hash is never rendered."""

    class Meta:
        model = User
        fields = ("email", "full_name", "is_active", *PRIVILEGED_FIELDS)

    def clean_email(self) -> str:
        email = normalize_email(self.cleaned_data.get("email"))
        if User.objects.filter(email=email).exclude(pk=self.instance.pk).exists():
            raise ValidationError("An account with this email address already exists.")
        return email


class SessionRevokingPasswordChangeForm(AdminPasswordChangeForm):  # type: ignore[type-arg]
    def save(self, commit: bool = True) -> Any:
        with transaction.atomic():
            user = super().save(commit=False)
            user.password_changed_at = timezone.now()
            user.save()
            revoke_user_sessions(user, RevokeReason.PASSWORD_CHANGED)
            record_after_commit("auth.password.changed_by_admin", user_id=user.pk)
        return user


@admin.register(User)
class UserAdmin(DjangoUserAdmin):  # type: ignore[type-arg]
    form = UserChangeForm
    add_form = UserCreationForm
    change_password_form = SessionRevokingPasswordChangeForm
    list_display = ("email", "full_name", "is_active", "is_staff", "is_superuser", "last_login")
    list_filter = ("is_active", "is_staff", "is_superuser")
    search_fields = ("email", "full_name")
    ordering = ("email",)
    readonly_fields = ("date_joined", "last_login", "password_changed_at")
    filter_horizontal = ("groups", "user_permissions")
    fieldsets = (
        (None, {"fields": ("email", "full_name")}),
        ("Status", {"fields": ("is_active",)}),
        ("Platform permissions", {"fields": PRIVILEGED_FIELDS}),
        ("Dates", {"fields": ("date_joined", "last_login", "password_changed_at")}),
    )
    add_fieldsets = (
        (None, {"classes": ("wide",), "fields": ("email", "full_name", "password1", "password2")}),
    )

    def get_readonly_fields(self, request: HttpRequest, obj: Any = None) -> tuple[str, ...]:
        fields = tuple(super().get_readonly_fields(request, obj))
        if not getattr(request.user, "is_superuser", False):
            fields += PRIVILEGED_FIELDS
        return fields

    def save_model(self, request: HttpRequest, obj: User, form: Any, change: bool) -> None:
        deactivating = change and "is_active" in form.changed_data and not obj.is_active
        if deactivating:
            obj.is_active = True  # deactivate through the service (locks, revokes sessions)
        super().save_model(request, obj, form, change)
        if deactivating:
            revoked = deactivate_user(obj, actor=request.user)  # type: ignore[arg-type]
            obj.is_active = False
            self.message_user(
                request, f"Account deactivated; {revoked} session(s) revoked.", messages.INFO
            )


@admin.register(AuthSession)
class AuthSessionAdmin(admin.ModelAdmin):  # type: ignore[type-arg]
    list_display = (
        "id",
        "user",
        "created_at",
        "last_rotated_at",
        "expires_at",
        "revoked_at",
        "revoke_reason",
    )
    list_filter = ("revoke_reason",)
    search_fields = ("user__email",)
    fields = (
        "id",
        "user",
        "created_at",
        "last_rotated_at",
        "expires_at",
        "revoked_at",
        "revoke_reason",
        "created_ip",
        "user_agent",
    )
    readonly_fields = fields
    actions = ("revoke_selected",)

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False

    def has_revoke_permission(self, request: HttpRequest) -> bool:
        return bool(getattr(request.user, "is_superuser", False))

    @admin.action(description="Revoke selected sessions", permissions=["revoke"])
    def revoke_selected(self, request: HttpRequest, queryset: QuerySet[AuthSession]) -> None:
        count = sum(revoke_session(session, RevokeReason.USER_REVOKED) for session in queryset)
        self.message_user(request, f"{count} session(s) revoked.", messages.INFO)
