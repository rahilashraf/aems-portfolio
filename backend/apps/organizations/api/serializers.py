"""Serializers with explicit field allowlists (ADR-0015).

Input serializers reject any key that is not a writable field (unknown, read-only or immutable),
so ``status``, ``slug``, ``created_by``, ``id`` or an organization reference can never be
smuggled into an update.
"""

from typing import Any

from rest_framework import serializers

from .. import invitations
from ..models import (
    Invitation,
    InvitationStatus,
    Membership,
    Organization,
    OrganizationStatus,
    OrganizationType,
)
from ..validators import normalize_slug, validate_slug, validate_timezone


class StrictInputSerializer(serializers.Serializer[Any]):
    def to_internal_value(self, data: Any) -> Any:
        if hasattr(data, "keys"):
            writable = {name for name, field in self.fields.items() if not field.read_only}
            unexpected = sorted(set(data.keys()) - writable)
            if unexpected:
                raise serializers.ValidationError(
                    {key: ["This field cannot be set."] for key in unexpected}
                )
        return super().to_internal_value(data)


class SlugField(serializers.CharField):
    def to_internal_value(self, data: Any) -> str:
        return normalize_slug(super().to_internal_value(data))


# ------------------------------------------------------------------------------- platform
class PlatformOrganizationSerializer(serializers.ModelSerializer[Organization]):
    created_by = serializers.UUIDField(source="created_by_id", read_only=True)

    class Meta:
        model = Organization
        fields = (
            "id",
            "name",
            "slug",
            "organization_type",
            "status",
            "timezone",
            "created_by",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


class PlatformOrganizationCreateSerializer(StrictInputSerializer):
    name = serializers.CharField(max_length=200)
    slug = SlugField(max_length=63, validators=[validate_slug])
    organization_type = serializers.ChoiceField(choices=OrganizationType.choices)
    timezone = serializers.CharField(max_length=64, default="UTC", validators=[validate_timezone])
    initial_owner_email = serializers.EmailField(max_length=254)


class PlatformOrganizationUpdateSerializer(StrictInputSerializer):
    name = serializers.CharField(max_length=200, required=False)
    organization_type = serializers.ChoiceField(choices=OrganizationType.choices, required=False)
    timezone = serializers.CharField(max_length=64, required=False, validators=[validate_timezone])
    status = serializers.ChoiceField(choices=OrganizationStatus.choices, required=False)


# --------------------------------------------------------------------------------- tenant
class OrganizationSerializer(serializers.ModelSerializer[Organization]):
    """What members see about their organization (no lifecycle or platform metadata)."""

    class Meta:
        model = Organization
        fields = ("id", "name", "slug", "organization_type", "timezone")
        read_only_fields = fields


class OrganizationProfileUpdateSerializer(StrictInputSerializer):
    name = serializers.CharField(max_length=200, required=False)
    timezone = serializers.CharField(max_length=64, required=False, validators=[validate_timezone])


class MembershipSummarySerializer(serializers.ModelSerializer[Membership]):
    class Meta:
        model = Membership
        fields = ("id", "status", "joined_at")
        read_only_fields = fields


class MyOrganizationSerializer(serializers.Serializer[Any]):
    """An entry of ``GET /organizations/``: the organization and the caller's membership."""

    organization = OrganizationSerializer(read_only=True)
    membership = MembershipSummarySerializer(source="*", read_only=True)


class MyRoleSerializer(serializers.Serializer[Any]):
    id = serializers.UUIDField(read_only=True)
    name = serializers.CharField(read_only=True)
    system_key = serializers.CharField(read_only=True, allow_null=True)


class OrganizationMembershipSerializer(serializers.Serializer[Any]):
    """``GET /organizations/{org_id}/me/``: membership, roles and effective permissions."""

    organization = OrganizationSerializer(read_only=True)
    membership = MembershipSummarySerializer(read_only=True)
    roles = MyRoleSerializer(many=True, read_only=True)
    permissions = serializers.ListField(child=serializers.CharField(), read_only=True)


# ----------------------------------------------------------------------------- invitations
def invitation_status(invitation: Invitation) -> str:
    """The stored status, with an unexpired-check for pending rows (expiry is time-based)."""
    if invitation.status == InvitationStatus.PENDING and invitation.expires_at <= invitations.now():
        return InvitationStatus.EXPIRED
    return str(invitation.status)


class InvitationRoleSerializer(serializers.Serializer[Any]):
    id = serializers.UUIDField(read_only=True)
    name = serializers.CharField(read_only=True)
    system_key = serializers.CharField(read_only=True, allow_null=True)


class InvitationSerializer(serializers.ModelSerializer[Invitation]):
    """Safe metadata for managers. Never the token or its digest."""

    organization = serializers.UUIDField(source="organization_id", read_only=True)
    invited_by = serializers.UUIDField(source="invited_by_id", read_only=True)
    accepted_by = serializers.UUIDField(source="accepted_by_id", read_only=True, allow_null=True)
    status = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()
    delivery_status = serializers.SerializerMethodField()

    class Meta:
        model = Invitation
        fields = (
            "id",
            "organization",
            "email",
            "roles",
            "status",
            "is_initial_owner",
            "invited_by",
            "created_at",
            "expires_at",
            "accepted_at",
            "accepted_by",
            "revoked_at",
            "delivery_status",
        )
        read_only_fields = fields

    def get_status(self, invitation: Invitation) -> str:
        return invitation_status(invitation)

    def get_roles(self, invitation: Invitation) -> list[dict[str, Any]]:
        links = sorted(invitation.role_links.all(), key=lambda link: (link.role.name, link.role_id))
        return [InvitationRoleSerializer(link.role).data for link in links]

    def get_delivery_status(self, invitation: Invitation) -> str | None:
        delivery = getattr(invitation, "email_delivery", None)
        return delivery.status if delivery is not None else None


class InvitationCreateSerializer(StrictInputSerializer):
    email = serializers.EmailField(max_length=254)
    role_ids = serializers.ListField(
        child=serializers.UUIDField(), allow_empty=False, max_length=20
    )


class InitialOwnerInvitationSerializer(StrictInputSerializer):
    email = serializers.EmailField(max_length=254)


class InvitationPreviewSerializer(serializers.Serializer[Any]):
    organization_name = serializers.CharField(read_only=True)
    email = serializers.CharField(read_only=True, help_text="Masked invited address.")
    status = serializers.CharField(read_only=True)
    expires_at = serializers.DateTimeField(read_only=True)
    next_step = serializers.ChoiceField(
        choices=["accept", "sign_in_or_create_account"], read_only=True
    )


class InvitationAcceptSerializer(StrictInputSerializer):
    """New accounts only: full name and password. Signed-in invitees send an empty body.

    The address always comes from the invitation; ``email`` and privilege fields are rejected.
    """

    full_name = serializers.CharField(max_length=255, required=False)
    password = serializers.CharField(
        max_length=4096, trim_whitespace=False, write_only=True, required=False
    )


class AcceptedOrganizationSerializer(serializers.Serializer[Any]):
    id = serializers.UUIDField(read_only=True)
    name = serializers.CharField(read_only=True)
    status = serializers.CharField(read_only=True)


class InvitationAcceptedSerializer(serializers.Serializer[Any]):
    organization = AcceptedOrganizationSerializer(read_only=True)
    membership = MembershipSummarySerializer(read_only=True)
    roles = InvitationRoleSerializer(many=True, read_only=True)
    account_created = serializers.BooleanField(read_only=True)
