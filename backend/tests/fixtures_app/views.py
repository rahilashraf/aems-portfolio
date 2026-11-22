"""Test-only views exercising error handling, pagination, filtering and request context."""

import time
from typing import Any

import structlog
from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.core.exceptions import SuspiciousOperation
from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_protect
from rest_framework import exceptions, generics, serializers
from rest_framework.authentication import BaseAuthentication
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, BasePermission
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import BaseThrottle

from apps.core.api.exceptions import ConflictError
from apps.core.api.permissions import PublicAccessGuard, PublicEndpoint
from apps.core.api.views import AemsAPIView, AemsViewSet
from apps.core.request_context import get_request_id

from .models import Widget

logger = structlog.get_logger("tests.fixtures_app")

SECRET_INTERNAL_MESSAGE = (
    "psycopg.OperationalError: password authentication failed for user aems_app "
    "at /srv/app/secret/config.py SELECT * FROM accounts WHERE token='tok_live_123'"
)


# ------------------------------------------------------------------ pagination / filtering
class WidgetSerializer(serializers.ModelSerializer[Widget]):
    class Meta:
        model = Widget
        fields = ("id", "name", "category", "quantity", "created_at", "updated_at")


class WidgetListView(PublicAccessGuard, generics.ListAPIView[Widget]):
    permission_classes = [PublicEndpoint]
    serializer_class = WidgetSerializer
    queryset = Widget.objects.all()
    filterset_fields = ["category", "quantity"]
    ordering_fields = ["name", "quantity", "created_at"]
    ordering = ["name"]


class WidgetFilterAllView(WidgetListView):
    filterset_fields = "__all__"  # type: ignore[assignment]


class WidgetNoOrderingFieldsView(WidgetListView):
    ordering_fields = None  # type: ignore[assignment]


class WidgetNoDefaultOrderingView(WidgetListView):
    ordering = None  # type: ignore[assignment]


# ------------------------------------------------------------------ permissions / auth / throttle
class ImplicitPermissionView(AemsAPIView):
    """Declares no permission_classes: the project default (DenyAll) applies."""

    def get(self, request: Request) -> Response:
        return Response({"reached": True})


class TestBearerAuthentication(BaseAuthentication):
    def authenticate(self, request: Request) -> None:
        return None

    def authenticate_header(self, request: Request) -> str:
        return 'Bearer realm="api"'


class RequireUser(BasePermission):
    def has_permission(self, request: Request, view: Any) -> bool:
        return bool(request.user)


class AuthRequiredView(AemsAPIView):
    authentication_classes = [TestBearerAuthentication]
    permission_classes = [RequireUser]

    def get(self, request: Request) -> Response:
        return Response({"reached": True})  # pragma: no cover


class AuthFailedView(AemsAPIView):
    authentication_classes = [TestBearerAuthentication]
    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:
        raise exceptions.AuthenticationFailed("Invalid token.")


class AlwaysThrottle(BaseThrottle):
    def allow_request(self, request: Request, view: Any) -> bool:
        return False

    def wait(self) -> float:
        return 42


class ThrottledView(AemsAPIView):
    permission_classes = [PublicEndpoint]
    throttle_classes = [AlwaysThrottle]

    def get(self, request: Request) -> Response:
        return Response({"reached": True})  # pragma: no cover


# ------------------------------------------------------------------ validation / media types
class ItemSerializer(serializers.Serializer[Any]):
    sku = serializers.CharField(max_length=5)


class EchoSerializer(serializers.Serializer[Any]):
    name = serializers.CharField(max_length=10)
    quantity = serializers.IntegerField(min_value=1)
    items = ItemSerializer(many=True, required=False)
    tags = serializers.ListField(child=serializers.CharField(max_length=3), required=False)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        if attrs.get("name") == "forbidden":
            raise serializers.ValidationError("This combination is not allowed.")
        return attrs


class EchoView(AemsAPIView):
    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:
        return Response({"ok": True})

    def post(self, request: Request) -> Response:
        serializer = EchoSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=201)


# ------------------------------------------------------------------ error translation
class ConflictView(AemsAPIView):
    permission_classes = [PublicEndpoint]

    def post(self, request: Request) -> Response:
        raise ConflictError()


class Django404View(AemsAPIView):
    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:
        raise Http404("No SecretModel matches the given query (tenant=42).")


class DjangoPermissionDeniedView(AemsAPIView):
    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:
        raise DjangoPermissionDenied("Internal rule R-17 rejected user 99.")


class DjangoValidationErrorView(AemsAPIView):
    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:
        raise DjangoValidationError({"email": ["Enter a valid email address."]})


class GenericApiExceptionView(AemsAPIView):
    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:
        raise exceptions.APIException()


class UnhandledErrorView(AemsAPIView):
    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:
        raise RuntimeError(SECRET_INTERNAL_MESSAGE)


# ------------------------------------------------------------------ plain Django views
def django_crash(request: HttpRequest) -> HttpResponse:
    raise RuntimeError(SECRET_INTERNAL_MESSAGE)


def django_suspicious(request: HttpRequest) -> HttpResponse:
    raise SuspiciousOperation("Tampered signature for session abc123")


def django_forbidden(request: HttpRequest) -> HttpResponse:
    raise DjangoPermissionDenied("Internal ACL details")


@csrf_protect
def django_csrf_protected(request: HttpRequest) -> HttpResponse:
    return JsonResponse({"ok": True})


# ------------------------------------------------------------------ request context / logging
class ContextView(AemsAPIView):
    """Sleeps briefly so concurrent requests overlap, then reports the bound request ID."""

    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:
        seen_before = get_request_id()
        time.sleep(float(request.query_params.get("sleep", "0.05")))
        logger.warning("fixture.context", marker=request.query_params.get("marker"))
        return Response(
            {
                "before": seen_before,
                "after": get_request_id(),
                "attribute": getattr(request, "request_id", None),
            }
        )


class SensitiveLoggingView(AemsAPIView):
    """Logs values under sensitive keys; redaction must remove them from the output."""

    permission_classes = [PublicEndpoint]

    def post(self, request: Request) -> Response:
        logger.warning(
            "fixture.sensitive",
            password=request.data.get("password"),
            token="tok_live_123",
            headers={"Authorization": request.headers.get("Authorization"), "Accept": "json"},
            nested={"api_key": "key_abc", "safe": "visible-value"},
        )
        return Response({"ok": True})


# ------------------------------------------------------------------ access-control violations
# Each of these would be reachable anonymously under plain DRF. PublicAccessGuard (and, for
# PublicEndpoint, its own allowlist check) must refuse them because their URL names are not in
# API_PUBLIC_ENDPOINTS.
class AlwaysAllow(BasePermission):
    """A custom permission that silently grants everything."""

    def has_permission(self, request: Request, view: Any) -> bool:
        return True


class EmptyPermissionsView(AemsAPIView):
    permission_classes = []

    def get(self, request: Request) -> Response:
        return Response({"reached": True})  # pragma: no cover


class CustomPermissiveView(AemsAPIView):
    permission_classes = [AlwaysAllow]

    def get(self, request: Request) -> Response:
        return Response({"reached": True})  # pragma: no cover


class DynamicPermissionsView(AemsAPIView):
    """Static checks see DenyAll; get_permissions() actually returns AllowAny."""

    def get_permissions(self) -> list[Any]:
        return [AllowAny()]

    def get(self, request: Request) -> Response:
        return Response({"reached": True})  # pragma: no cover


class UnlistedPublicEndpointView(AemsAPIView):
    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:
        return Response({"reached": True})  # pragma: no cover


class ActionPermissionsViewSet(AemsViewSet):
    """``list`` is allowlisted; ``unsafe`` and ``dynamic`` grant AllowAny per action."""

    permission_classes = [PublicEndpoint]

    def get_permissions(self) -> list[Any]:
        if self.action == "dynamic":
            return [AllowAny()]
        return list(super().get_permissions())

    def list(self, request: Request) -> Response:
        return Response({"reached": "list"})

    @action(detail=False, methods=["get"], permission_classes=[AllowAny])
    def unsafe(self, request: Request) -> Response:
        return Response({"reached": "unsafe"})  # pragma: no cover

    @action(detail=False, methods=["get"])
    def dynamic(self, request: Request) -> Response:
        return Response({"reached": "dynamic"})  # pragma: no cover


class UnguardedPublicView(generics.GenericAPIView[Any]):
    """Lacks PublicAccessGuard (flagged by core.E004); PublicEndpoint still checks the allowlist."""

    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:
        return Response({"reached": True})


# ------------------------------------------------------------------ sensitive exception content
# Deliberately sensitive values: none of them may appear in API responses or logs.
SENSITIVE_VALUES = {
    "db_password": "db-pass-Z9q2",
    "token": "tok_live_51HsECRET",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.c2lnbmF0dXJlLXZhbHVl",
    "bearer": "Bearer abcdef0123456789",
    "email": "student.secret@example.org",
    "sql_literal": "s3cr3t-literal",
    "local": "local-variable-secret-77",
    "query_secret": "reset-qs-secret-55",
}
SENSITIVE_EXCEPTION_TEXT = (
    "could not connect: postgresql://aems_app:"  # noqa: S608 - synthetic text, never executed
    f"{SENSITIVE_VALUES['db_password']}@db.internal:5432/aems "
    f"password={SENSITIVE_VALUES['db_password']} token={SENSITIVE_VALUES['token']} "
    f"Authorization: {SENSITIVE_VALUES['bearer']} jwt {SENSITIVE_VALUES['jwt']} "
    f"url https://api.example.org/reset/?token={SENSITIVE_VALUES['query_secret']}\n"
    f"DETAIL:  Key (email)=({SENSITIVE_VALUES['email']}) already exists.\n"
    # Synthetic database error text (never executed as SQL).
    "LINE 1: SELECT * FROM accounts WHERE secret = "
    f"'{SENSITIVE_VALUES['sql_literal']}'"
)


class LeakyDomainError(ConflictError):
    """A (mis)written domain error whose message embeds a credential."""


class NonDomainApiError(exceptions.APIException):
    status_code = 418
    default_code = "teapot"


class SensitiveErrorsView(AemsAPIView):
    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:
        kind = request.query_params.get("kind")
        local_secret = SENSITIVE_VALUES["local"]  # must never be rendered (no locals in tracebacks)
        if kind == "domain":
            raise LeakyDomainError(f"Duplicate entry; {SENSITIVE_EXCEPTION_TEXT}")
        if kind == "non-domain":
            raise NonDomainApiError(SENSITIVE_EXCEPTION_TEXT)
        if kind == "permission":
            raise exceptions.PermissionDenied(f"Denied for token={SENSITIVE_VALUES['token']}")
        if kind == "django-validation":
            raise DjangoValidationError({"email": [SENSITIVE_EXCEPTION_TEXT]})
        raise RuntimeError(SENSITIVE_EXCEPTION_TEXT + local_secret[:0])


class CredentialsSerializer(serializers.Serializer[Any]):
    username = serializers.CharField(max_length=20)
    password = serializers.CharField(max_length=8)
    api_token = serializers.CharField(required=False)
    notes = serializers.ListField(child=serializers.IntegerField(), required=False)

    def validate_username(self, value: str) -> str:
        raise serializers.ValidationError(
            f"User {value} rejected; token={SENSITIVE_VALUES['token']}"
        )

    def validate_password(self, value: str) -> str:
        raise serializers.ValidationError(f"Password {value!r} is too weak.")

    def validate_api_token(self, value: str) -> str:
        raise serializers.ValidationError(f"Token {value} is revoked.")


class SensitiveValidationView(AemsAPIView):
    permission_classes = [PublicEndpoint]

    def post(self, request: Request) -> Response:
        CredentialsSerializer(data=request.data).is_valid(raise_exception=True)
        return Response(status=204)  # pragma: no cover
