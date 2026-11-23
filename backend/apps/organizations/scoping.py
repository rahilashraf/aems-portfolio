"""Central tenant resolution for organization-scoped API views (ADR-0003 layers 1-6, ADR-0015).

Every tenant endpoint lives under ``/api/v1/organizations/{org_id}/…`` and uses
:class:`OrganizationScopedViewMixin` (enforced by the route-coverage meta-test). For each request:

1. The organization id comes **only** from the URL (``<uuid:org_id>``). A malformed id does not
   match the route (404). Headers and request bodies are never consulted.
2. The caller must be authenticated; otherwise 401, before anything about the organization is
   looked up.
3. One query resolves the caller's **active** membership in an **active** organization. An unknown
   organization, another tenant's organization, a provisioning or suspended organization, a
   suspended membership and an inactive account all produce the **same 404**, and platform
   administrators get no bypass.
4. The view's permission classes then run with ``request.membership`` available (default deny).
5. Request bodies that try to name an organization (``organization``/``organization_id``) are
   rejected with 400: the tenant comes from the URL only.
6. Querysets come from :meth:`~OrganizationScopedViewMixin.get_scoped_queryset`, and nested or
   referenced objects from :func:`get_scoped_object_or_404` /
   :class:`TenantScopedPrimaryKeyRelatedField`, which filter by the resolved organization. An id
   belonging to organization A used under organization B's URL is "not found".
"""

from typing import Any, cast

import structlog
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db.models import QuerySet
from rest_framework import exceptions, serializers
from rest_framework.request import Request

from apps.core.api.permissions import is_authenticated
from apps.core.net import client_ip as request_client_ip
from apps.core.security_events import record_security_event

from .models import Membership, Organization
from .selectors import resolve_active_membership
from .tenancy import TENANT_FIELD, MissingTenantContextError, TenantScopedModel

ORGANIZATION_URL_KWARG = "org_id"
# Body keys that would let a client choose the tenant (layer 2).
TENANT_BODY_KEYS = frozenset({"organization", "organization_id", "org", "org_id", "tenant"})


class OrganizationScopedViewMixin:
    """Resolve and enforce the organization from the URL for every request.

    Place it **before** the project base view class::

        class ThingView(OrganizationScopedViewMixin, AemsGenericAPIView):
            tenant_model = Thing
            permission_classes = [TenantMemberReadOnly]
    """

    organization_url_kwarg = ORGANIZATION_URL_KWARG
    tenant_model: type[TenantScopedModel] | None = None

    organization: Organization
    membership: Membership
    kwargs: dict[str, Any]

    def check_permissions(self, request: Request) -> None:
        if not is_authenticated(getattr(request, "user", None)):
            # Unauthenticated: the normal checks answer 401 before any tenant lookup.
            super().check_permissions(request)  # type: ignore[misc]
            self.permission_denied(request)  # type: ignore[attr-defined]  # defensive
        self.resolve_tenant(request)
        super().check_permissions(request)  # type: ignore[misc]

    def resolve_tenant(self, request: Request) -> None:
        organization_id = self.kwargs.get(self.organization_url_kwarg)
        membership = resolve_active_membership(request.user, organization_id)
        if membership is None:
            record_security_event(
                "tenant.access_denied",
                outcome="failure",
                user_id=getattr(request.user, "pk", None),
                client_ip=request_client_ip(request),
                organization_id=str(organization_id),
            )
            raise exceptions.NotFound()
        self.membership = membership
        self.organization = membership.organization
        request.membership = membership  # type: ignore[attr-defined]
        request.organization = membership.organization  # type: ignore[attr-defined]
        structlog.contextvars.bind_contextvars(organization_id=str(membership.organization_id))

    def initial(self, request: Request, *args: Any, **kwargs: Any) -> None:
        super().initial(request, *args, **kwargs)  # type: ignore[misc]
        reject_tenant_body_fields(request)

    def get_scoped_queryset(self) -> QuerySet[Any]:
        if self.tenant_model is None:
            msg = f"{type(self).__name__} must set tenant_model."
            raise ImproperlyConfigured(msg)
        organization = getattr(self, "organization", None)
        if organization is None:
            msg = "Tenant context has not been resolved."
            raise MissingTenantContextError(msg)
        return cast(QuerySet[Any], self.tenant_model.objects.for_organization(organization))

    def get_queryset(self) -> QuerySet[Any]:
        return self.get_scoped_queryset()


def reject_tenant_body_fields(request: Request) -> None:
    """Layer 2: a request body may never name the organization."""
    if request.method in ("GET", "HEAD", "OPTIONS", "DELETE"):
        return
    data = request.data
    if not hasattr(data, "keys"):
        return
    offending = sorted(TENANT_BODY_KEYS & set(data.keys()))
    if offending:
        raise exceptions.ValidationError(
            {
                key: ["The organization is taken from the URL and cannot be set in the body."]
                for key in offending
            }
        )


def get_scoped_object_or_404(
    model: type[TenantScopedModel], organization: Organization | None, **lookup: Any
) -> Any:
    """Fetch one tenant-owned object of ``organization``; anything else is 404.

    Use for every nested lookup (``…/organizations/{org_id}/things/{thing_id}/``). Malformed ids
    are 404 too, never 500.
    """
    queryset = model.objects.for_organization(organization)
    try:
        obj = queryset.filter(**lookup).first()
    except (ValidationError, ValueError, TypeError) as exc:
        raise exceptions.NotFound() from exc
    if obj is None:
        raise exceptions.NotFound()
    return obj


class TenantScopedPrimaryKeyRelatedField(serializers.PrimaryKeyRelatedField):  # type: ignore[type-arg]
    """A reference in a request body that must belong to the view's organization.

    The serializer context must contain the resolved ``organization`` (fail closed otherwise).
    Ids of other organizations are reported exactly like ids that do not exist.
    """

    def __init__(self, *, model: type[TenantScopedModel], **kwargs: Any) -> None:
        self.tenant_model = model
        super().__init__(**kwargs)

    def get_queryset(self) -> QuerySet[Any]:
        organization = self.context.get(TENANT_FIELD)
        return cast(QuerySet[Any], self.tenant_model.objects.for_organization(organization))


def tenant_serializer_context(view: OrganizationScopedViewMixin) -> dict[str, Any]:
    return {TENANT_FIELD: view.organization}


__all__ = [
    "ORGANIZATION_URL_KWARG",
    "TENANT_BODY_KEYS",
    "OrganizationScopedViewMixin",
    "TenantScopedPrimaryKeyRelatedField",
    "get_scoped_object_or_404",
    "reject_tenant_body_fields",
    "tenant_serializer_context",
]
