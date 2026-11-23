"""Test-only tenant endpoints built on the production tenancy primitives (ADR-0015).

They let the isolation matrix exercise cross-tenant reads and writes, nested lookups and body
references before real tenant resources exist. Writes are allowed to any active member here via a
test-only permission; production tenant views use ``HasOrgPermission``.
"""

from typing import Any

from rest_framework import serializers, status
from rest_framework.permissions import BasePermission
from rest_framework.request import Request
from rest_framework.response import Response

from apps.core.api.views import AemsGenericAPIView
from apps.organizations.scoping import (
    OrganizationScopedViewMixin,
    TenantScopedPrimaryKeyRelatedField,
    get_scoped_object_or_404,
    tenant_serializer_context,
)

from .models import TenantNote


class TestOnlyAnyMember(BasePermission):
    def has_permission(self, request: Request, view: Any) -> bool:
        return getattr(request, "membership", None) is not None


class TenantNoteSerializer(serializers.ModelSerializer[TenantNote]):
    parent = TenantScopedPrimaryKeyRelatedField(  # type: ignore[assignment]
        model=TenantNote, required=False, allow_null=True
    )

    class Meta:
        model = TenantNote
        fields = ("id", "title", "parent")
        read_only_fields = ("id",)

    def create(self, validated_data: dict[str, Any]) -> TenantNote:
        return TenantNote.objects.create(
            organization=self.context["organization"], **validated_data
        )


class TenantNoteListView(OrganizationScopedViewMixin, AemsGenericAPIView):
    tenant_model = TenantNote
    permission_classes = [TestOnlyAnyMember]
    serializer_class = TenantNoteSerializer
    ordering_fields = ["title"]
    ordering = "title"

    def get(self, request: Request, org_id: Any) -> Response:
        page = self.paginate_queryset(self.filter_queryset(self.get_queryset()))
        return self.get_paginated_response(self.get_serializer(page, many=True).data)

    def post(self, request: Request, org_id: Any) -> Response:
        serializer = TenantNoteSerializer(
            data=request.data, context=tenant_serializer_context(self)
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class TenantNoteDetailView(OrganizationScopedViewMixin, AemsGenericAPIView):
    tenant_model = TenantNote
    permission_classes = [TestOnlyAnyMember]
    serializer_class = TenantNoteSerializer

    def get(self, request: Request, org_id: Any, note_id: Any) -> Response:
        note = get_scoped_object_or_404(TenantNote, self.organization, pk=note_id)
        return Response(TenantNoteSerializer(note).data)

    def patch(self, request: Request, org_id: Any, note_id: Any) -> Response:
        note = get_scoped_object_or_404(TenantNote, self.organization, pk=note_id)
        serializer = TenantNoteSerializer(
            note, data=request.data, partial=True, context=tenant_serializer_context(self)
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
