"""RBAC API serializers: explicit read fields and strict input allowlists (ADR-0017).

Input serializers reject unknown keys, so ``organization``, ``system_key``, ``is_system``,
``user`` or timestamps can never be mass-assigned.
"""

from typing import Any

from rest_framework import serializers

from apps.organizations.api.serializers import StrictInputSerializer
from apps.organizations.models import Membership, MembershipStatus

from ..models import Permission, Role
from ..registry import registry

MAX_ROLES_PER_MEMBER = 20
MAX_PERMISSIONS_PER_ROLE = 50


class RoleSummarySerializer(serializers.ModelSerializer[Role]):
    class Meta:
        model = Role
        fields = ("id", "name", "system_key")
        read_only_fields = fields


def role_permission_codes(role: Role) -> list[str]:
    """Owner: every active catalog permission (dynamic). Others: their active codes."""
    if role.is_owner:
        return sorted(registry.active_codes())
    return sorted(c for c in (p.code for p in role.permissions.all()) if registry.is_active(c))


class RoleSerializer(serializers.ModelSerializer[Role]):
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = Role
        fields = (
            "id",
            "name",
            "description",
            "is_system",
            "system_key",
            "permissions",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields

    def get_permissions(self, role: Role) -> list[str]:
        return role_permission_codes(role)


class PermissionCodesField(serializers.ListField):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(
            child=serializers.CharField(max_length=100),
            max_length=MAX_PERMISSIONS_PER_ROLE,
            allow_empty=True,
            **kwargs,
        )

    def to_internal_value(self, data: Any) -> list[str]:
        codes: list[str] = super().to_internal_value(data)
        unknown = registry.unknown_or_inactive(codes)
        if unknown:
            raise serializers.ValidationError(
                f"Unknown or deprecated permission: {', '.join(unknown)}.", code="unknown"
            )
        return sorted(set(codes))


class RoleCreateSerializer(StrictInputSerializer):
    name = serializers.CharField(max_length=100)
    description = serializers.CharField(max_length=255, required=False, allow_blank=True)
    permissions = PermissionCodesField(required=False)


class RoleUpdateSerializer(StrictInputSerializer):
    name = serializers.CharField(max_length=100, required=False)
    description = serializers.CharField(max_length=255, required=False, allow_blank=True)
    permissions = PermissionCodesField(required=False)


class PermissionSerializer(serializers.ModelSerializer[Permission]):
    class Meta:
        model = Permission
        fields = ("code", "description", "category")
        read_only_fields = fields


class MemberUserSerializer(serializers.Serializer[Any]):
    id = serializers.UUIDField(read_only=True)
    email = serializers.EmailField(read_only=True)
    full_name = serializers.CharField(read_only=True)


class MemberSerializer(serializers.ModelSerializer[Membership]):
    user = MemberUserSerializer(read_only=True)
    roles = serializers.SerializerMethodField()

    class Meta:
        model = Membership
        fields = ("id", "user", "status", "joined_at", "roles")
        read_only_fields = fields

    def get_roles(self, membership: Membership) -> list[dict[str, Any]]:
        links = sorted(membership.role_links.all(), key=lambda link: (link.role.name, link.role_id))
        return [RoleSummarySerializer(link.role).data for link in links]


class MemberStatusUpdateSerializer(StrictInputSerializer):
    status = serializers.ChoiceField(choices=MembershipStatus.choices)


class MemberRolesSerializer(StrictInputSerializer):
    """Role ids are resolved by the service within the URL organization only: an id of another
    organization is reported exactly like an id that does not exist."""

    role_ids = serializers.ListField(
        child=serializers.UUIDField(), allow_empty=True, max_length=MAX_ROLES_PER_MEMBER
    )
