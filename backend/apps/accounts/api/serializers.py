from typing import Any

from rest_framework import serializers

from apps.accounts.models import AuthSession, User


class LoginSerializer(serializers.Serializer[Any]):
    email = serializers.CharField(max_length=254, trim_whitespace=True)
    password = serializers.CharField(max_length=4096, trim_whitespace=False, write_only=True)


class UserSerializer(serializers.ModelSerializer[User]):
    """The authenticated user's own profile. Never exposes password data."""

    class Meta:
        model = User
        fields = ("id", "email", "full_name", "is_staff", "date_joined", "last_login")
        read_only_fields = ("id", "email", "is_staff", "date_joined", "last_login")


class ProfileUpdateSerializer(serializers.ModelSerializer[User]):
    class Meta:
        model = User
        fields = ("full_name",)
        extra_kwargs = {"full_name": {"required": True, "allow_blank": False}}


class TokenResponseSerializer(serializers.Serializer[Any]):
    access_token = serializers.CharField()
    token_type = serializers.CharField(default="Bearer")
    expires_in = serializers.IntegerField(help_text="Access-token lifetime in seconds.")


class LoginResponseSerializer(TokenResponseSerializer):
    user = UserSerializer()


class CsrfResponseSerializer(serializers.Serializer[Any]):
    detail = serializers.CharField()


class PasswordChangeSerializer(serializers.Serializer[Any]):
    current_password = serializers.CharField(
        max_length=4096, trim_whitespace=False, write_only=True
    )
    new_password = serializers.CharField(max_length=4096, trim_whitespace=False, write_only=True)


class PasswordResetRequestSerializer(serializers.Serializer[Any]):
    email = serializers.CharField(max_length=254, trim_whitespace=True)


class PasswordResetConfirmSerializer(serializers.Serializer[Any]):
    uid = serializers.CharField(max_length=64)
    token = serializers.CharField(max_length=128)
    new_password = serializers.CharField(max_length=4096, trim_whitespace=False, write_only=True)


class DetailSerializer(serializers.Serializer[Any]):
    detail = serializers.CharField()


class AuthSessionSerializer(serializers.ModelSerializer[AuthSession]):
    current = serializers.SerializerMethodField()

    class Meta:
        model = AuthSession
        fields = (
            "id",
            "created_at",
            "last_rotated_at",
            "expires_at",
            "created_ip",
            "user_agent",
            "current",
        )
        read_only_fields = fields

    def get_current(self, obj: AuthSession) -> bool:
        current_id = self.context.get("current_session_id")
        return current_id is not None and str(obj.id) == str(current_id)


class RevokedCountSerializer(serializers.Serializer[Any]):
    revoked = serializers.IntegerField()
