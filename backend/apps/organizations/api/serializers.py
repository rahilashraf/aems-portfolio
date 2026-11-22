"""Serializers with explicit field allowlists (ADR-0015).

Input serializers reject any key that is not a writable field (unknown, read-only or immutable),
so ``status``, ``slug``, ``created_by``, ``id`` or an organization reference can never be
smuggled into an update.
"""

from typing import Any

from rest_framework import serializers

from ..models import Membership, Organization, OrganizationStatus, OrganizationType
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


class OrganizationMembershipSerializer(serializers.Serializer[Any]):
    """``GET /organizations/{org_id}/me/``. Roles and permissions are added in Batch 6."""

    organization = OrganizationSerializer(read_only=True)
    membership = MembershipSummarySerializer(source="*", read_only=True)
