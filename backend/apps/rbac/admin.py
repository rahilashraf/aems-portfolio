"""Read-only admin views of the permission catalog, roles and role assignments.

RBAC changes go through :mod:`apps.rbac.services` only (tenant API), which enforce the
delegation, self-modification and Owner rules, the Owner invariant and audit atomicity. The admin
therefore cannot add, change or delete these records, so it offers no path around them.
"""

from django.contrib import admin

from apps.organizations.admin import ReadOnlyAdmin

from .models import MembershipRole, Permission, Role


@admin.register(Permission)
class PermissionAdmin(ReadOnlyAdmin):
    list_display = ("code", "category", "is_deprecated")
    list_filter = ("category", "is_deprecated")
    ordering = ("code",)
    actions = None


@admin.register(Role)
class RoleAdmin(ReadOnlyAdmin):
    list_display = ("name", "organization", "system_key", "is_system", "created_at")
    list_filter = ("is_system", "system_key")
    search_fields = ("name",)
    ordering = ("organization", "name")
    actions = None


@admin.register(MembershipRole)
class MembershipRoleAdmin(ReadOnlyAdmin):
    list_display = ("id", "organization", "membership", "role", "assigned_at")
    ordering = ("-assigned_at",)
    actions = None
