"""Read-only admin views of organizations and memberships.

Organization lifecycle changes go through services and the platform API only: the admin cannot
create, edit, activate or delete organizations or memberships, so it offers no path around the
provisioning lifecycle or the ownership invariant (ADR-0005, ADR-0015).
"""

from typing import Any

from django.contrib import admin
from django.http import HttpRequest

from .models import Invitation, Membership, Organization


class ReadOnlyAdmin(admin.ModelAdmin):  # type: ignore[type-arg]
    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False


@admin.register(Organization)
class OrganizationAdmin(ReadOnlyAdmin):
    list_display = ("name", "slug", "organization_type", "status", "created_at")
    list_filter = ("status", "organization_type")
    search_fields = ("name", "slug")
    ordering = ("name",)


@admin.register(Membership)
class MembershipAdmin(ReadOnlyAdmin):
    list_display = ("id", "organization", "status", "joined_at")
    list_filter = ("status",)
    ordering = ("-joined_at",)


@admin.register(Invitation)
class InvitationAdmin(ReadOnlyAdmin):
    """Read-only. The token digest is never displayed; invitations change only through services."""

    list_display = ("id", "organization", "status", "is_initial_owner", "created_at", "expires_at")
    list_filter = ("status", "is_initial_owner")
    exclude = ("token_hash",)
    ordering = ("-created_at",)
    actions = None
