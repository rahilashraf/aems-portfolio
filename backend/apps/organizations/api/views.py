"""Organization API views (Batch 4; ADR-0015).

Active routes:

- Platform (staff + model permission): ``GET|POST /platform/organizations/``,
  ``GET|PATCH /platform/organizations/{id}/``.
- Self: ``GET /organizations/`` (the caller's active memberships in active organizations).
- Tenant (``OrganizationScopedViewMixin``): ``GET /organizations/{org_id}/``,
  ``GET /organizations/{org_id}/me/`` (any active member), ``PATCH /organizations/{org_id}/``
  (requires ``organization.update``: fails closed until Batch 6).

Deferred: members, roles, permissions (Batch 6), invitations (Batch 7), audit logs (Batch 5).
"""

from typing import Any

from django.db.models import F, QuerySet
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from apps.core.api.views import AemsGenericAPIView
from apps.core.net import client_ip

from .. import selectors, services
from ..models import Membership, Organization
from ..permissions import HasOrgPermission, IsPlatformAdministrator
from ..scoping import OrganizationScopedViewMixin
from . import serializers as s

PLATFORM_TAG = "platform"
TENANT_TAG = "organizations"


# ------------------------------------------------------------------------------- platform
class PlatformOrganizationListView(AemsGenericAPIView):
    permission_classes = [IsPlatformAdministrator]
    serializer_class = s.PlatformOrganizationSerializer
    filterset_fields = ["status", "organization_type"]
    ordering_fields = ["name", "slug", "created_at", "status"]
    ordering = "name"

    def get_queryset(self) -> QuerySet[Organization]:
        return selectors.organizations_for_platform()

    @extend_schema(
        operation_id="platform_organizations_list",
        summary="List organizations (platform administration)",
        tags=[PLATFORM_TAG],
    )
    def get(self, request: Request) -> Response:
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        return self.get_paginated_response(self.get_serializer(page, many=True).data)

    @extend_schema(
        operation_id="platform_organizations_create",
        summary="Create an organization",
        description=(
            "Creates the organization in `provisioning` status. It becomes `active` only when an "
            "initial Owner accepts their invitation (Batch 7); until then no tenant API is "
            "available for it."
        ),
        request=s.PlatformOrganizationCreateSerializer,
        responses={201: s.PlatformOrganizationSerializer},
        tags=[PLATFORM_TAG],
    )
    def post(self, request: Request) -> Response:
        serializer = s.PlatformOrganizationCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        organization = services.create_organization(
            actor=request.user, client_ip=client_ip(request), **serializer.validated_data
        )
        return Response(
            s.PlatformOrganizationSerializer(organization).data, status=status.HTTP_201_CREATED
        )


class PlatformOrganizationDetailView(AemsGenericAPIView):
    permission_classes = [IsPlatformAdministrator]
    filter_backends: list[Any] = []  # single object: no list filtering or ordering
    serializer_class = s.PlatformOrganizationSerializer
    lookup_url_kwarg = "organization_id"

    def get_queryset(self) -> QuerySet[Organization]:
        return selectors.organizations_for_platform()

    @extend_schema(
        operation_id="platform_organizations_retrieve",
        summary="Get an organization (platform administration)",
        tags=[PLATFORM_TAG],
    )
    def get(self, request: Request, organization_id: Any) -> Response:
        return Response(self.get_serializer(self.get_object()).data)

    @extend_schema(
        operation_id="platform_organizations_update",
        summary="Update an organization (platform administration)",
        description=(
            "Editable: `name`, `organization_type`, `timezone`, `status`. The only status change "
            "allowed is `active` → `suspended` (effective immediately). Activation is not "
            "available: it requires a verified active Owner (Batches 6/7). `slug`, `created_by` "
            "and other fields cannot be changed."
        ),
        request=s.PlatformOrganizationUpdateSerializer,
        responses={200: s.PlatformOrganizationSerializer},
        tags=[PLATFORM_TAG],
    )
    def patch(self, request: Request, organization_id: Any) -> Response:
        organization = self.get_object()
        serializer = s.PlatformOrganizationUpdateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        organization = services.update_organization(
            actor=request.user,
            organization=organization,
            changes=dict(serializer.validated_data),
            client_ip=client_ip(request),
        )
        return Response(s.PlatformOrganizationSerializer(organization).data)


# ------------------------------------------------------------------------------------ self
class MyOrganizationListView(AemsGenericAPIView):
    """The caller's organizations. Not tenant-scoped: it lists across the caller's memberships."""

    permission_classes = [IsAuthenticated]
    serializer_class = s.MyOrganizationSerializer
    ordering_fields = ["name", "slug", "joined_at"]
    ordering = "name"

    def get_queryset(self) -> QuerySet[Membership]:
        return selectors.memberships_for_user(self.request.user).annotate(
            name=F("organization__name"), slug=F("organization__slug")
        )

    @extend_schema(
        operation_id="organizations_list",
        summary="List my organizations",
        description=(
            "Organizations where the caller has an active membership and the organization is "
            "active. Provisioning and suspended organizations and suspended memberships are not "
            "listed."
        ),
        tags=[TENANT_TAG],
    )
    def get(self, request: Request) -> Response:
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        return self.get_paginated_response(self.get_serializer(page, many=True).data)


# ---------------------------------------------------------------------------------- tenant
class OrganizationDetailView(OrganizationScopedViewMixin, AemsGenericAPIView):
    permission_classes = [HasOrgPermission]
    member_actions = ("get",)
    required_permissions = {"patch": ("organization.update",)}
    serializer_class = s.OrganizationSerializer

    @extend_schema(
        operation_id="organizations_retrieve",
        summary="Get the organization",
        tags=[TENANT_TAG],
    )
    def get(self, request: Request, org_id: Any) -> Response:
        return Response(s.OrganizationSerializer(self.organization).data)

    @extend_schema(
        operation_id="organizations_update",
        summary="Update the organization profile",
        description=(
            "Requires the `organization.update` permission. Organization roles arrive in Batch 6; "
            "until then no member holds it and this endpoint answers 403."
        ),
        request=s.OrganizationProfileUpdateSerializer,
        responses={200: s.OrganizationSerializer},
        tags=[TENANT_TAG],
    )
    def patch(self, request: Request, org_id: Any) -> Response:  # pragma: no cover - Batch 6
        serializer = s.OrganizationProfileUpdateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        organization = services.update_organization_profile(
            actor=request.user,
            organization=self.organization,
            changes=dict(serializer.validated_data),
            client_ip=client_ip(request),
        )
        return Response(s.OrganizationSerializer(organization).data)


class OrganizationMembershipView(OrganizationScopedViewMixin, AemsGenericAPIView):
    permission_classes = [HasOrgPermission]
    member_actions = ("get",)
    serializer_class = s.OrganizationMembershipSerializer

    @extend_schema(
        operation_id="organizations_me_retrieve",
        summary="My membership in the organization",
        tags=[TENANT_TAG],
    )
    def get(self, request: Request, org_id: Any) -> Response:
        return Response(s.OrganizationMembershipSerializer(self.membership).data)
