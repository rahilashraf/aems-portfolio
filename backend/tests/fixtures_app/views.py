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
from rest_framework.permissions import BasePermission
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import BaseThrottle
from rest_framework.views import APIView

from apps.core.api.exceptions import ConflictError
from apps.core.api.permissions import PublicEndpoint
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


class WidgetListView(generics.ListAPIView[Widget]):
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
class ImplicitPermissionView(APIView):
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


class AuthRequiredView(APIView):
    authentication_classes = [TestBearerAuthentication]
    permission_classes = [RequireUser]

    def get(self, request: Request) -> Response:
        return Response({"reached": True})  # pragma: no cover


class AuthFailedView(APIView):
    authentication_classes = [TestBearerAuthentication]
    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:
        raise exceptions.AuthenticationFailed("Invalid token.")


class AlwaysThrottle(BaseThrottle):
    def allow_request(self, request: Request, view: Any) -> bool:
        return False

    def wait(self) -> float:
        return 42


class ThrottledView(APIView):
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


class EchoView(APIView):
    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:
        return Response({"ok": True})

    def post(self, request: Request) -> Response:
        serializer = EchoSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=201)


# ------------------------------------------------------------------ error translation
class ConflictView(APIView):
    permission_classes = [PublicEndpoint]

    def post(self, request: Request) -> Response:
        raise ConflictError()


class Django404View(APIView):
    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:
        raise Http404("No SecretModel matches the given query (tenant=42).")


class DjangoPermissionDeniedView(APIView):
    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:
        raise DjangoPermissionDenied("Internal rule R-17 rejected user 99.")


class DjangoValidationErrorView(APIView):
    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:
        raise DjangoValidationError({"email": ["Enter a valid email address."]})


class GenericApiExceptionView(APIView):
    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:
        raise exceptions.APIException()


class UnhandledErrorView(APIView):
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
class ContextView(APIView):
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


class SensitiveLoggingView(APIView):
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
