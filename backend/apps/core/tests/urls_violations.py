"""URLconf used only to verify that the access-control system checks detect violations."""

from typing import Any

from django.http import HttpRequest, HttpResponse
from django.urls import include, path
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.routers import SimpleRouter
from rest_framework.views import APIView

from apps.core.api.permissions import DenyAll, PublicEndpoint
from apps.core.api.views import AemsAPIView, AemsViewSet


class UnlistedPublicView(AemsAPIView):
    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:  # pragma: no cover
        return Response()


class BareAllowAnyView(AemsAPIView):
    permission_classes = [AllowAny]

    def get(self, request: Request) -> Response:  # pragma: no cover
        return Response()


class CustomAllowAny(AllowAny):
    pass


class CustomAllowAnyView(AemsAPIView):
    permission_classes = [CustomAllowAny]

    def get(self, request: Request) -> Response:  # pragma: no cover
        return Response()


class EmptyPermissionsView(AemsAPIView):
    permission_classes = []

    def get(self, request: Request) -> Response:  # pragma: no cover
        return Response()


class UnguardedView(APIView):
    permission_classes = [DenyAll]

    def get(self, request: Request) -> Response:  # pragma: no cover
        return Response()


class DeniedView(AemsAPIView):
    permission_classes = [DenyAll]

    def get(self, request: Request) -> Response:  # pragma: no cover
        return Response()


class ActionViewSet(AemsViewSet):
    permission_classes = [DenyAll]

    def list(self, request: Request) -> Response:  # pragma: no cover
        return Response()

    @action(detail=False, methods=["get"], permission_classes=[AllowAny])
    def opened(self, request: Request) -> Response:  # pragma: no cover
        return Response()

    @action(detail=False, methods=["get"], permission_classes=[])
    def emptied(self, request: Request) -> Response:  # pragma: no cover
        return Response()


def plain_django(request: HttpRequest) -> HttpResponse:  # pragma: no cover
    return HttpResponse()


router = SimpleRouter()
router.register("actions", ActionViewSet, basename="actions")

nested: tuple[list[Any], str] = (
    [
        path("bare/", BareAllowAnyView.as_view(), name="bare-allow-any"),
        path("unnamed/", BareAllowAnyView.as_view()),
    ],
    "nested",
)

urlpatterns = [
    path("public/", UnlistedPublicView.as_view(), name="unlisted-public"),
    path("custom/", CustomAllowAnyView.as_view(), name="custom-allow-any"),
    path("empty/", EmptyPermissionsView.as_view(), name="empty-permissions"),
    path("unguarded/", UnguardedView.as_view(), name="unguarded"),
    path("denied/", DeniedView.as_view(), name="denied"),
    path("denied-again/", DeniedView.as_view(), name="denied"),  # duplicate name
    path("plain/", plain_django, name="plain-django"),
    path("plain-again/", plain_django, name="plain-django"),  # duplicate, but not a DRF view
    path("ns/", include(nested, namespace="nested")),
    path("", include(router.urls)),
]
