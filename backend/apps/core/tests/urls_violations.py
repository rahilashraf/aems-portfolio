"""URLconf used only to verify that the public-endpoint system checks detect violations."""

from django.http import HttpRequest, HttpResponse
from django.urls import include, path
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.core.api.permissions import DenyAll, PublicEndpoint


class UnlistedPublicView(APIView):
    permission_classes = [PublicEndpoint]

    def get(self, request: Request) -> Response:  # pragma: no cover
        return Response()


class BareAllowAnyView(APIView):
    permission_classes = [AllowAny]

    def get(self, request: Request) -> Response:  # pragma: no cover
        return Response()


class DeniedView(APIView):
    permission_classes = [DenyAll]

    def get(self, request: Request) -> Response:  # pragma: no cover
        return Response()


def plain_django(request: HttpRequest) -> HttpResponse:  # pragma: no cover
    return HttpResponse()


nested = (
    [
        path("bare/", BareAllowAnyView.as_view(), name="bare-allow-any"),
        path("unnamed/", BareAllowAnyView.as_view()),
    ],
    "nested",
)

urlpatterns = [
    path("public/", UnlistedPublicView.as_view(), name="unlisted-public"),
    path("denied/", DeniedView.as_view(), name="denied"),
    path("plain/", plain_django, name="plain-django"),
    path("ns/", include(nested, namespace="nested")),
]
