from rest_framework import serializers

from ..models import AuditLog


class AuditLogSerializer(serializers.ModelSerializer[AuditLog]):
    organization = serializers.UUIDField(source="organization_id", read_only=True, allow_null=True)
    actor = serializers.UUIDField(source="actor_id", read_only=True, allow_null=True)

    class Meta:
        model = AuditLog
        fields = (
            "id",
            "created_at",
            "action",
            "outcome",
            "organization",
            "actor",
            "actor_email",
            "target_type",
            "target_id",
            "changes",
            "metadata",
            "ip_address",
            "user_agent",
            "request_id",
        )
        read_only_fields = fields
