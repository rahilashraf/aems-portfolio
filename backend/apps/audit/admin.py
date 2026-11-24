"""Read-only admin view of the audit log.

Requires the explicit ``audit.view_auditlog`` permission (Django's view permission). Nothing can
be added, changed or deleted, and there are no bulk actions, so the admin offers no way around the
append-only rules (which the database trigger enforces anyway).
"""

from typing import Any

from django.contrib import admin
from django.http import HttpRequest

from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):  # type: ignore[type-arg]
    list_display = ("created_at", "action", "outcome", "actor_email", "organization", "target_type")
    list_filter = ("outcome", "action")
    search_fields = ("action", "actor_email", "target_id", "request_id")
    date_hierarchy = "created_at"
    ordering = ("-created_at", "-id")
    list_per_page = 50
    show_full_result_count = False
    actions = None

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False

    def get_readonly_fields(self, request: HttpRequest, obj: Any = None) -> list[str]:
        return [field.name for field in AuditLog._meta.fields]
