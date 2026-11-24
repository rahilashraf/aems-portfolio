"""Member, role and permission-catalog APIs under ``/organizations/{org_id}/`` (ADR-0017).

Every view uses the standard tenant infrastructure (enforced by the route-coverage meta-test):
``OrganizationScopedViewMixin`` resolves the organization from the URL and the caller's active
membership (404 otherwise), then ``HasOrgPermission`` checks the declared permissions (default
deny). Lookups of members and roles are scoped to that organization, so an id of another
organization is 404. Mutations go through :mod:`apps.rbac.services`, which re-check permissions,
escalation rules and the Owner invariant under the organization lock and write audit records in
the same transaction.
"""

from typing import Any

from django.db.models import Prefetch, QuerySet
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response

from apps.core.api.views import AemsGenericAPIView
from apps.core.net import client_ip
from apps.organizations.models import Membership
from apps.organizations.permissions import HasOrgPermission
from apps.organizations.scoping import OrganizationScopedViewMixin, get_scoped_object_or_404

from .. import services
from ..models import MembershipRole, Permission, Role
from ..registry import registry
from . import serializers as s

TAG = "organization access"


def _members(queryset: QuerySet[Membership]) -> QuerySet[Membership]:
    return queryset.select_related("user").prefetch_related(
        Prefetch("role_links", queryset=MembershipRole.objects.select_related("role"))
    )


def _roles(queryset: QuerySet[Role]) -> QuerySet[Role]:
    return queryset.prefetch_related("permissions")


# -------------------------------------------------------------------------------- members
class MemberListView(OrganizationScopedViewMixin, AemsGenericAPIView):
    tenant_model = Membership
    permission_classes = [HasOrgPermission]
    required_permissions = {"get": ("members.view",)}
    serializer_class = s.MemberSerializer
    filterset_fields = ["status"]
    ordering_fields = ["joined_at"]
    ordering = "joined_at"

    @extend_schema(
        operation_id="organization_members_list",
        summary="List members",
        description="Requires `members.view`.",
        tags=[TAG],
    )
    def get(self, request: Request, org_id: Any) -> Response:
        queryset = _members(self.filter_queryset(self.get_queryset()))
        page = self.paginate_queryset(queryset)
        return self.get_paginated_response(self.get_serializer(page, many=True).data)


class MemberDetailView(OrganizationScopedViewMixin, AemsGenericAPIView):
    tenant_model = Membership
    permission_classes = [HasOrgPermission]
    required_permissions = {
        "get": ("members.view",),
        "patch": ("members.manage",),
        "delete": ("members.manage",),
    }
    serializer_class = s.MemberSerializer
    filter_backends: list[Any] = []

    def _member(self, membership_id: Any) -> Membership:
        member = get_scoped_object_or_404(Membership, self.organization, pk=membership_id)
        return _members(Membership.objects.for_organization(self.organization)).get(pk=member.pk)

    @extend_schema(
        operation_id="organization_members_retrieve",
        summary="Get a member",
        description="Requires `members.view`.",
        tags=[TAG],
    )
    def get(self, request: Request, org_id: Any, membership_id: Any) -> Response:
        return Response(s.MemberSerializer(self._member(membership_id)).data)

    @extend_schema(
        operation_id="organization_members_update",
        summary="Suspend or reactivate a member",
        description=(
            "Requires `members.manage`. Body: `status` (`active` or `suspended`). You cannot "
            "change your own membership, a member who holds permissions you do not hold, or an "
            "Owner unless you are an Owner. Suspending the last active Owner is refused with "
            "409 `last_owner`."
        ),
        request=s.MemberStatusUpdateSerializer,
        responses={200: s.MemberSerializer},
        tags=[TAG],
    )
    def patch(self, request: Request, org_id: Any, membership_id: Any) -> Response:
        member = self._member(membership_id)
        serializer = s.MemberStatusUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        services.update_membership_status(
            actor=request.user,
            organization=self.organization,
            membership_id=member.pk,
            status=serializer.validated_data["status"],
            client_ip=client_ip(request),
        )
        return Response(s.MemberSerializer(self._member(member.pk)).data)

    @extend_schema(
        operation_id="organization_members_destroy",
        summary="Remove a member",
        description=(
            "Requires `members.manage`. Deletes the membership and its role assignments (the user "
            "account is not affected). Same restrictions as suspension; removing the last active "
            "Owner is refused with 409 `last_owner`."
        ),
        responses={204: None},
        tags=[TAG],
    )
    def delete(self, request: Request, org_id: Any, membership_id: Any) -> Response:
        member = self._member(membership_id)
        services.remove_membership(
            actor=request.user,
            organization=self.organization,
            membership_id=member.pk,
            client_ip=client_ip(request),
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class MemberRolesView(OrganizationScopedViewMixin, AemsGenericAPIView):
    tenant_model = Membership
    permission_classes = [HasOrgPermission]
    required_permissions = {"put": ("members.manage",)}
    serializer_class = s.MemberSerializer
    filter_backends: list[Any] = []

    @extend_schema(
        operation_id="organization_members_roles_replace",
        summary="Replace a member's roles",
        description=(
            "Requires `members.manage`. Body: `role_ids`, the complete new set (roles of this "
            "organization only). You can only assign or remove roles whose permissions you hold; "
            "only Owners grant or remove the Owner role. You cannot change your own roles, except "
            "that an Owner may remove their own Owner role while another active Owner remains."
        ),
        request=s.MemberRolesSerializer,
        responses={200: s.MemberSerializer},
        tags=[TAG],
    )
    def put(self, request: Request, org_id: Any, membership_id: Any) -> Response:
        member = get_scoped_object_or_404(Membership, self.organization, pk=membership_id)
        serializer = s.MemberRolesSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        services.replace_membership_roles(
            actor=request.user,
            organization=self.organization,
            membership_id=member.pk,
            role_ids=serializer.validated_data["role_ids"],
            client_ip=client_ip(request),
        )
        updated = _members(Membership.objects.for_organization(self.organization)).get(pk=member.pk)
        return Response(s.MemberSerializer(updated).data)


# ---------------------------------------------------------------------------------- roles
class RoleListView(OrganizationScopedViewMixin, AemsGenericAPIView):
    tenant_model = Role
    permission_classes = [HasOrgPermission]
    required_permissions = {"get": ("roles.view",), "post": ("roles.manage",)}
    serializer_class = s.RoleSerializer
    filterset_fields = ["is_system"]
    ordering_fields = ["name", "created_at"]
    ordering = "name"

    @extend_schema(
        operation_id="organization_roles_list",
        summary="List roles",
        description="Requires `roles.view`.",
        tags=[TAG],
    )
    def get(self, request: Request, org_id: Any) -> Response:
        queryset = _roles(self.filter_queryset(self.get_queryset()))
        page = self.paginate_queryset(queryset)
        return self.get_paginated_response(self.get_serializer(page, many=True).data)

    @extend_schema(
        operation_id="organization_roles_create",
        summary="Create a custom role",
        description=(
            "Requires `roles.manage`. You can only include permissions you hold. Names are unique "
            "per organization, ignoring case (409 `role_name_taken`)."
        ),
        request=s.RoleCreateSerializer,
        responses={201: s.RoleSerializer},
        tags=[TAG],
    )
    def post(self, request: Request, org_id: Any) -> Response:
        serializer = s.RoleCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        role = services.create_role(
            actor=request.user,
            organization=self.organization,
            client_ip=client_ip(request),
            **serializer.validated_data,
        )
        return Response(s.RoleSerializer(role).data, status=status.HTTP_201_CREATED)


class RoleDetailView(OrganizationScopedViewMixin, AemsGenericAPIView):
    tenant_model = Role
    permission_classes = [HasOrgPermission]
    required_permissions = {
        "get": ("roles.view",),
        "patch": ("roles.manage",),
        "delete": ("roles.manage",),
    }
    serializer_class = s.RoleSerializer
    filter_backends: list[Any] = []

    def _role(self, role_id: Any) -> Role:
        role: Role = get_scoped_object_or_404(Role, self.organization, pk=role_id)
        return role

    @extend_schema(
        operation_id="organization_roles_retrieve",
        summary="Get a role",
        description="Requires `roles.view`.",
        tags=[TAG],
    )
    def get(self, request: Request, org_id: Any, role_id: Any) -> Response:
        return Response(s.RoleSerializer(self._role(role_id)).data)

    @extend_schema(
        operation_id="organization_roles_update",
        summary="Update a role",
        description=(
            "Requires `roles.manage`. `permissions` replaces the role's permission set. You can "
            "only add or remove permissions you hold. The Owner role cannot be changed; Admin and "
            "Member keep their names but their permissions are editable (409 "
            "`system_role_protected`)."
        ),
        request=s.RoleUpdateSerializer,
        responses={200: s.RoleSerializer},
        tags=[TAG],
    )
    def patch(self, request: Request, org_id: Any, role_id: Any) -> Response:
        role = self._role(role_id)
        serializer = s.RoleUpdateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        updated = services.update_role(
            actor=request.user,
            organization=self.organization,
            role_id=role.pk,
            changes=dict(serializer.validated_data),
            client_ip=client_ip(request),
        )
        return Response(s.RoleSerializer(self._role(updated.pk)).data)

    @extend_schema(
        operation_id="organization_roles_destroy",
        summary="Delete a custom role",
        description=(
            "Requires `roles.manage`. System roles cannot be deleted (409 "
            "`system_role_protected`); a role still assigned to members cannot be deleted (409 "
            "`role_in_use`)."
        ),
        responses={204: None},
        tags=[TAG],
    )
    def delete(self, request: Request, org_id: Any, role_id: Any) -> Response:
        role = self._role(role_id)
        services.delete_role(
            actor=request.user,
            organization=self.organization,
            role_id=role.pk,
            client_ip=client_ip(request),
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class PermissionListView(OrganizationScopedViewMixin, AemsGenericAPIView):
    """The permission catalog (global definitions; read through the organization's API)."""

    permission_classes = [HasOrgPermission]
    required_permissions = {"get": ("roles.view",)}
    serializer_class = s.PermissionSerializer
    filter_backends: list[Any] = []

    @extend_schema(
        operation_id="organization_permissions_list",
        summary="List assignable permissions",
        description="Requires `roles.view`. Active (non-deprecated) catalog permissions.",
        tags=[TAG],
    )
    def get(self, request: Request, org_id: Any) -> Response:
        queryset = Permission.objects.filter(
            is_deprecated=False, code__in=registry.active_codes()
        ).order_by("code", "id")
        page = self.paginate_queryset(queryset)
        return self.get_paginated_response(self.get_serializer(page, many=True).data)
