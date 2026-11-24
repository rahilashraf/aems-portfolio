"""Organization API views (Batch 4; ADR-0015).

Active routes:

- Platform (staff + model permission): ``GET|POST /platform/organizations/``,
  ``GET|PATCH /platform/organizations/{id}/``.
- Self: ``GET /organizations/`` (the caller's active memberships in active organizations).
- Tenant (``OrganizationScopedViewMixin``): ``GET /organizations/{org_id}/`` (requires
  ``organization.view``), ``GET /organizations/{org_id}/me/`` (any active member),
  ``PATCH /organizations/{org_id}/``
  (requires ``organization.update``, re-checked in the service under the organization lock).

Members, roles and permissions live in :mod:`apps.rbac.api.views`; audit logs in
:mod:`apps.audit.api.views`. Invitations arrive in Batch 7.
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
from apps.rbac import engine
from apps.rbac.models import MembershipRole, Role

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
    # AEMS-017: reading the profile needs organization.view (granted to the Member role by
    # default). The caller's own membership stays available to every member at me/.
    required_permissions = {"get": ("organization.view",), "patch": ("organization.update",)}
    serializer_class = s.OrganizationSerializer

    @extend_schema(
        operation_id="organizations_retrieve",
        summary="Get the organization",
        description=(
            "Requires the `organization.view` permission (held by the default Member, Admin and "
            "Owner roles). Every active member can still read their own membership, roles and "
            "permissions at `GET /organizations/{org_id}/me/`."
        ),
        tags=[TENANT_TAG],
    )
    def get(self, request: Request, org_id: Any) -> Response:
        return Response(s.OrganizationSerializer(self.organization).data)

    @extend_schema(
        operation_id="organizations_update",
        summary="Update the organization profile",
        description=(
            "Requires the `organization.update` permission. Editable: `name`, `timezone`. The "
            "slug, type and status cannot be changed here."
        ),
        request=s.OrganizationProfileUpdateSerializer,
        responses={200: s.OrganizationSerializer},
        tags=[TENANT_TAG],
    )
    def patch(self, request: Request, org_id: Any) -> Response:
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
        summary="My membership, roles and effective permissions in the organization",
        tags=[TENANT_TAG],
    )
    def get(self, request: Request, org_id: Any) -> Response:
        links = MembershipRole.objects.for_organization(self.organization).filter(
            membership=self.membership
        )
        roles = sorted((link.role for link in links.select_related("role")), key=_role_order)
        data = {
            "organization": self.organization,
            "membership": self.membership,
            "roles": roles,
            "permissions": sorted(engine.effective_permissions(self.membership)),
        }
        return Response(s.OrganizationMembershipSerializer(data).data)


def _role_order(role: Role) -> tuple[str, str]:
    return (role.name, str(role.pk))
