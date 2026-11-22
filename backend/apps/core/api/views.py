"""Core API views: the v1 API root and environment-gated API documentation."""

from typing import Any

from django.conf import settings
from django.http import Http404, HttpRequest, HttpResponseBase
from drf_spectacular.utils import extend_schema
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView
from rest_framework import serializers
from rest_framework.generics import GenericAPIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet, ViewSet

from apps.core.errors import page_not_found

from .permissions import PublicAccessGuard, PublicEndpoint

API_VERSION = "v1"


# Project base classes: every DRF view must include PublicAccessGuard (system check core.E004).
class AemsAPIView(PublicAccessGuard, APIView):
    pass


class AemsGenericAPIView(PublicAccessGuard, GenericAPIView[Any]):
    pass


class AemsViewSet(PublicAccessGuard, ViewSet):
    pass


class AemsGenericViewSet(PublicAccessGuard, GenericViewSet[Any]):
    pass


class ApiRootSerializer(serializers.Serializer[Any]):
    service = serializers.CharField()
    api_version = serializers.CharField()


class ApiRootView(AemsAPIView):
    """Public API entry point. Exposes no version numbers of the software stack."""

    permission_classes = [PublicEndpoint]

    @extend_schema(
        operation_id="api_root",
        summary="API root",
        description="Identifies the service and API version. Does not require authentication.",
        responses={200: ApiRootSerializer},
        tags=["meta"],
    )
    def get(self, request: Request) -> Response:
        return Response({"service": "aems", "api_version": API_VERSION})


class DocsGateMixin:
    """Serve API documentation only when ``settings.API_DOCS_ENABLED`` is true.

    The gate is evaluated per request (not at URL import time) and answers with a Problem Details
    404 when disabled, so a disabled environment reveals nothing about the API surface.
    Production settings force it off until staff authentication exists (Batch 3+).
    """

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        if not settings.API_DOCS_ENABLED:
            return page_not_found(request, Http404())
        response: HttpResponseBase = super().dispatch(request, *args, **kwargs)  # type: ignore[misc]
        return response


class SchemaView(DocsGateMixin, PublicAccessGuard, SpectacularAPIView):
    pass


class SwaggerView(DocsGateMixin, PublicAccessGuard, SpectacularSwaggerView):
    pass


class RedocView(DocsGateMixin, PublicAccessGuard, SpectacularRedocView):
    pass
