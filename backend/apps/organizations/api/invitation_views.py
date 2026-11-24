"""Invitation APIs (Batch 7; ADR-0018).

- Tenant (``/organizations/{org_id}/invitations/``): list, create and revoke, behind
  ``invitations.manage`` and the standard tenant infrastructure (route-coverage meta-test).
- Platform (``/platform/organizations/{id}/initial-owner-invitation/``): view, issue or reissue,
  and revoke the initial Owner invitation of a provisioning organization, behind explicit Django
  model permissions.
- Public, token-scoped (``/invitations/{token}/`` and ``…/accept/``): explicitly allowlisted. They
  reveal nothing about the organization beyond its name, answer every unusable token with the same
  404, are rate limited per client IP, and are never cacheable or sent as a Referer.
"""

from typing import Any

from django.db.models import Prefetch, QuerySet
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import status
from rest_framework.exceptions import NotFound
from rest_framework.request import Request
from rest_framework.response import Response

from apps.accounts.authentication import WWW_AUTHENTICATE
from apps.core.api.permissions import PublicEndpoint
from apps.core.api.views import AemsAPIView, AemsGenericAPIView
from apps.core.net import client_ip
from apps.rbac.models import Role

from .. import invitations
from ..models import Invitation, InvitationRole, Organization
from ..permissions import HasOrgPermission, IsPlatformAdministrator
from ..scoping import OrganizationScopedViewMixin, get_scoped_object_or_404
from . import serializers as s

TENANT_TAG = "organization access"
PLATFORM_TAG = "platform"
PUBLIC_TAG = "invitations"


def _with_details(queryset: QuerySet[Invitation]) -> QuerySet[Invitation]:
    return queryset.select_related("email_delivery").prefetch_related(
        Prefetch("role_links", queryset=InvitationRole.objects.select_related("role"))
    )


# --------------------------------------------------------------------------------- tenant
class InvitationListView(OrganizationScopedViewMixin, AemsGenericAPIView):
    tenant_model = Invitation
    permission_classes = [HasOrgPermission]
    required_permissions = {"get": ("invitations.manage",), "post": ("invitations.manage",)}
    serializer_class = s.InvitationSerializer
    filterset_fields = ["status"]
    ordering_fields = ["created_at", "expires_at"]
    ordering = "-created_at"

    @extend_schema(
        operation_id="organization_invitations_list",
        summary="List invitations",
        description=(
            "Requires `invitations.manage`. Safe metadata only: tokens and their digests are "
            "never returned. `status` reports `expired` for pending invitations past their expiry."
        ),
        tags=[TENANT_TAG],
    )
    def get(self, request: Request, org_id: Any) -> Response:
        queryset = _with_details(self.filter_queryset(self.get_queryset()))
        page = self.paginate_queryset(queryset)
        return self.get_paginated_response(self.get_serializer(page, many=True).data)

    @extend_schema(
        operation_id="organization_invitations_create",
        summary="Invite someone",
        description=(
            "Requires `invitations.manage`. `role_ids` must be roles of this organization whose "
            "permissions you hold; only Owners can invite with the Owner role. An existing member "
            "(409 `already_member`) or an address with a pending invitation (409 "
            "`invitation_already_pending`; revoke it first) cannot be invited. The email is sent "
            "asynchronously; `delivery_status` starts as `pending`."
        ),
        request=s.InvitationCreateSerializer,
        responses={201: s.InvitationSerializer},
        tags=[TENANT_TAG],
    )
    def post(self, request: Request, org_id: Any) -> Response:
        serializer = s.InvitationCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        invitation = invitations.create_invitation(
            actor=request.user,
            organization=self.organization,
            email=serializer.validated_data["email"],
            role_ids=serializer.validated_data["role_ids"],
            client_ip=client_ip(request),
        )
        created = _with_details(Invitation.objects.for_organization(self.organization)).get(
            pk=invitation.pk
        )
        return Response(s.InvitationSerializer(created).data, status=status.HTTP_201_CREATED)


class InvitationRevokeView(OrganizationScopedViewMixin, AemsGenericAPIView):
    tenant_model = Invitation
    permission_classes = [HasOrgPermission]
    required_permissions = {"post": ("invitations.manage",)}
    serializer_class = s.InvitationSerializer
    filter_backends: list[Any] = []

    @extend_schema(
        operation_id="organization_invitations_revoke",
        summary="Revoke an invitation",
        description=(
            "Requires `invitations.manage` and the permissions the invitation grants (Owner "
            "invitations: Owners only). Only pending invitations can be revoked (409 "
            "`invitation_not_pending`); revoking never affects an accepted membership."
        ),
        request=None,
        responses={200: s.InvitationSerializer},
        tags=[TENANT_TAG],
    )
    def post(self, request: Request, org_id: Any, invitation_id: Any) -> Response:
        invitation = get_scoped_object_or_404(Invitation, self.organization, pk=invitation_id)
        invitations.revoke_invitation(
            actor=request.user,
            organization=self.organization,
            invitation_id=invitation.pk,
            client_ip=client_ip(request),
        )
        revoked = _with_details(Invitation.objects.for_organization(self.organization)).get(
            pk=invitation.pk
        )
        return Response(s.InvitationSerializer(revoked).data)


# ------------------------------------------------------------------------------- platform
class IsPlatformOnboardingAdministrator(IsPlatformAdministrator):
    """Viewing needs ``view_organization``; changing needs the dedicated onboarding permission."""

    method_permissions = {
        "GET": "organizations.view_organization",
        "HEAD": "organizations.view_organization",
        "OPTIONS": "organizations.view_organization",
        "POST": "organizations.manage_initial_owner_invitation",
    }


def _organization(organization_id: Any) -> Organization:
    organization: Organization = get_object_or_404(Organization, pk=organization_id)
    return organization


class PlatformInitialOwnerInvitationView(AemsAPIView):
    permission_classes = [IsPlatformOnboardingAdministrator]

    @extend_schema(
        operation_id="platform_initial_owner_invitation_retrieve",
        summary="The pending initial Owner invitation",
        responses={200: s.InvitationSerializer},
        tags=[PLATFORM_TAG],
    )
    def get(self, request: Request, organization_id: Any) -> Response:
        pending = invitations.pending_initial_owner_invitation(_organization(organization_id))
        if pending is None:
            raise NotFound()
        detailed = _with_details(Invitation.objects.filter(pk=pending.pk)).get()
        return Response(s.InvitationSerializer(detailed).data)

    @extend_schema(
        operation_id="platform_initial_owner_invitation_issue",
        summary="Issue or reissue the initial Owner invitation",
        description=(
            "Provisioning organizations only (409 `organization_not_provisioning`). Revokes the "
            "pending initial Owner invitation, if any, and issues a new one to `email`. Requires "
            "the `organizations.manage_initial_owner_invitation` permission."
        ),
        request=s.InitialOwnerInvitationSerializer,
        responses={201: s.InvitationSerializer},
        tags=[PLATFORM_TAG],
    )
    def post(self, request: Request, organization_id: Any) -> Response:
        serializer = s.InitialOwnerInvitationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        invitation = invitations.reissue_initial_owner_invitation(
            actor=request.user,
            organization=_organization(organization_id),
            email=serializer.validated_data["email"],
            client_ip=client_ip(request),
        )
        detailed = _with_details(Invitation.objects.filter(pk=invitation.pk)).get()
        return Response(s.InvitationSerializer(detailed).data, status=status.HTTP_201_CREATED)


class PlatformInitialOwnerInvitationRevokeView(AemsAPIView):
    permission_classes = [IsPlatformOnboardingAdministrator]

    @extend_schema(
        operation_id="platform_initial_owner_invitation_revoke",
        summary="Revoke the pending initial Owner invitation",
        request=None,
        responses={200: s.InvitationSerializer},
        tags=[PLATFORM_TAG],
    )
    def post(self, request: Request, organization_id: Any) -> Response:
        invitation = invitations.revoke_initial_owner_invitation(
            actor=request.user,
            organization=_organization(organization_id),
            client_ip=client_ip(request),
        )
        detailed = _with_details(Invitation.objects.filter(pk=invitation.pk)).get()
        return Response(s.InvitationSerializer(detailed).data)


# --------------------------------------------------------------------------------- public
TOKEN_PARAMETER = OpenApiParameter(
    "token",
    str,
    OpenApiParameter.PATH,
    description="The invitation token from the emailed link. Treat it as a credential.",
)
SENSITIVE_HEADERS = {
    "Cache-Control": "no-store, private",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
}


class PublicInvitationView(AemsAPIView):
    """Token-scoped public route: optional bearer authentication, never cacheable."""

    permission_classes = [PublicEndpoint]

    def initial(self, request: Request, *args: Any, **kwargs: Any) -> None:
        super().initial(request, *args, **kwargs)
        invitations.check_rate_limit(client_ip(request))

    def finalize_response(self, request: Request, response: Any, *args: Any, **kwargs: Any) -> Any:
        response = super().finalize_response(request, response, *args, **kwargs)
        for header, value in SENSITIVE_HEADERS.items():
            response[header] = value
        return response

    def get_authenticate_header(self, request: Request) -> str:
        return WWW_AUTHENTICATE


class InvitationPreviewView(PublicInvitationView):
    @extend_schema(
        operation_id="invitations_preview",
        summary="Preview an invitation",
        description=(
            "Public. Returns the organization name, the masked invited address, the expiry and "
            "the next step. Unknown, expired, revoked and used tokens all answer the same 404 "
            "`invitation_invalid`. Whether an account exists for the address is not revealed."
        ),
        parameters=[TOKEN_PARAMETER],
        responses={200: s.InvitationPreviewSerializer},
        tags=[PUBLIC_TAG],
    )
    def get(self, request: Request, token: str) -> Response:
        preview = invitations.preview_invitation(token, viewer=request.user)
        return Response(s.InvitationPreviewSerializer(preview).data)


class InvitationAcceptView(PublicInvitationView):
    @extend_schema(
        operation_id="invitations_accept",
        summary="Accept an invitation",
        description=(
            "Public. If an account exists for the invited address, sign in as that account "
            "(bearer token) and send an empty body; otherwise 401 `sign_in_required`, and another "
            "signed-in account gets 403 `invitation_email_mismatch`. If no account exists, send "
            "`full_name` and `password` to create it with the invited address. Membership, roles, "
            "invitation consumption and, for the initial Owner, organization activation happen "
            "in one transaction."
        ),
        parameters=[TOKEN_PARAMETER],
        request=s.InvitationAcceptSerializer,
        responses={200: s.InvitationAcceptedSerializer},
        tags=[PUBLIC_TAG],
    )
    def post(self, request: Request, token: str) -> Response:
        serializer = s.InvitationAcceptSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = invitations.accept_invitation(
            token,
            user=request.user,
            full_name=serializer.validated_data.get("full_name"),
            password=serializer.validated_data.get("password"),
            client_ip=client_ip(request),
        )
        roles: list[Role] = sorted(result.roles, key=lambda r: (r.name, str(r.pk)))
        data = {
            "organization": result.organization,
            "membership": result.membership,
            "roles": roles,
            "account_created": result.account_created,
        }
        return Response(s.InvitationAcceptedSerializer(data).data)
