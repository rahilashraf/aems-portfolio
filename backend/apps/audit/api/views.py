"""Audit read APIs (ADR-0016).

- ``GET /api/v1/organizations/{org_id}/audit-logs/``: the organization's own events. Tenant
  resolution first (404 for non-members and inactive organizations), then the ``audit.view``
  organization permission, which no one can hold before Batch 6 roles: the endpoint fails closed
  with 403 until then.
- ``GET /api/v1/platform/audit-logs/``: events that belong to **no** organization (accounts,
  authentication, platform actions, denied tenant access), for active staff holding
  ``audit.view_auditlog``. Organization events are never served here.
"""

from typing import Any

from django.db.models import QuerySet
from drf_spectacular.utils import extend_schema
from rest_framework.request import Request
from rest_framework.response import Response

from apps.core.api.filtering import AllowlistFilterBackend
from apps.core.api.views import AemsGenericAPIView
from apps.organizations.permissions import HasOrgPermission
from apps.organizations.scoping import OrganizationScopedViewMixin

from ..models import AuditLog
from ..permissions import IsPlatformAuditor
from .filters import AuditLogFilterSet
from .pagination import AuditCursorPagination
from .serializers import AuditLogSerializer


class AuditLogListBase(AemsGenericAPIView):
    serializer_class = AuditLogSerializer
    pagination_class = AuditCursorPagination
    # No ordering filter: the cursor pagination's fixed ordering applies.
    filter_backends = [AllowlistFilterBackend]
    filterset_class = AuditLogFilterSet

    def list_response(self) -> Response:
        page = self.paginate_queryset(self.filter_queryset(self.get_queryset()))
        return self.get_paginated_response(AuditLogSerializer(page, many=True).data)


class OrganizationAuditLogListView(OrganizationScopedViewMixin, AuditLogListBase):
    tenant_model = AuditLog
    permission_classes = [HasOrgPermission]
    required_permissions = {"get": ("audit.view",)}

    @extend_schema(
        operation_id="organizations_audit_logs_list",
        summary="List the organization's audit events",
        description=(
            "Requires the `audit.view` organization permission. Organization roles arrive in "
            "Batch 6; until then no member holds it and this endpoint answers 403."
        ),
        tags=["organizations"],
    )
    def get(self, request: Request, org_id: Any) -> Response:
        return self.list_response()


class PlatformAuditLogListView(AuditLogListBase):
    permission_classes = [IsPlatformAuditor]

    def get_queryset(self) -> QuerySet[AuditLog]:
        return AuditLog.objects.platform_events()

    @extend_schema(
        operation_id="platform_audit_logs_list",
        summary="List platform audit events (no organization)",
        description=(
            "Account, authentication and platform events, and denied tenant access. Requires an "
            "active staff account with the `audit.view_auditlog` permission. Organization events "
            "are not included."
        ),
        tags=["platform"],
    )
    def get(self, request: Request) -> Response:
        return self.list_response()
