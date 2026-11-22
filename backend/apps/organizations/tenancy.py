"""Tenant-scoping foundation for organization-owned models (ADR-0003, ADR-0015).

Every tenant-owned model inherits :class:`TenantScopedModel`:

- ``organization`` is a non-null, indexed foreign key (``PROTECT``). It is not editable through
  model forms or ``ModelSerializer`` (``editable=False``), and it cannot change after creation:
  ``save()`` and ``QuerySet.update()/bulk_update()`` refuse to reassign it. No reassignment
  service exists; adding one requires its own reviewed, explicitly named code path.
- Queries for tenant data go through ``Model.objects.for_organization(org)``, which **fails
  closed**: without a saved :class:`~apps.organizations.models.Organization` it raises
  :class:`MissingTenantContextError` instead of returning unscoped rows.
- Tenant API views obtain querysets only from ``OrganizationScopedViewMixin.get_scoped_queryset()``
  (enforced by the route-coverage meta-test).

The default manager still returns all rows, because Django internals (admin, migrations, related
lookups, deletion collectors) require it. Cross-tenant reads are confined to named selectors
(``apps.organizations.selectors``), each documented as a narrow bypass. These are the paths that
PostgreSQL row-level security (Phase 2, ADR-0003) would have to allow explicitly.
"""

from typing import TYPE_CHECKING, Any, Self

from django.db import models

from apps.core.models import BaseModel

if TYPE_CHECKING:
    from .models import Organization

TENANT_FIELD = "organization"
_TENANT_FIELDS = frozenset({TENANT_FIELD, f"{TENANT_FIELD}_id"})


class MissingTenantContextError(RuntimeError):
    """A tenant query or write was attempted without a resolved organization."""


class TenantReassignmentError(RuntimeError):
    """An ordinary update tried to move a tenant-owned row to another organization."""


class TenantQuerySet(models.QuerySet[Any]):
    def for_organization(self, organization: "Organization | None") -> Self:
        """Rows of one organization. Raises if the organization is missing or unsaved."""
        state = getattr(organization, "_state", None)
        if organization is None or state is None or state.adding:
            msg = "Tenant queries require a resolved organization."
            raise MissingTenantContextError(msg)
        return self.filter(**{TENANT_FIELD: organization})

    def update(self, **kwargs: Any) -> int:
        if _TENANT_FIELDS & kwargs.keys():
            msg = "The organization of tenant-owned rows cannot be changed by update()."
            raise TenantReassignmentError(msg)
        return super().update(**kwargs)

    def bulk_update(self, objs: Any, fields: Any, batch_size: int | None = None) -> int:
        if _TENANT_FIELDS & set(fields):
            msg = "The organization of tenant-owned rows cannot be changed by bulk_update()."
            raise TenantReassignmentError(msg)
        return super().bulk_update(objs, fields, batch_size=batch_size)


TenantManager = models.Manager.from_queryset(TenantQuerySet)


class TenantScopedModel(BaseModel):
    """Abstract base for every organization-owned model."""

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.PROTECT,
        related_name="+",
        editable=False,
        db_index=True,
    )

    objects = TenantManager()

    _loaded_organization_id: Any = None

    class Meta:
        abstract = True

    @classmethod
    def from_db(cls, db: str | None, field_names: Any, values: Any) -> Self:
        instance = super().from_db(db, field_names, values)
        instance._loaded_organization_id = instance.__dict__.get("organization_id")
        return instance

    def save(self, *args: Any, **kwargs: Any) -> None:
        if getattr(self, "organization_id", None) is None:
            msg = f"{type(self).__name__} requires an organization."
            raise MissingTenantContextError(msg)
        if not self._state.adding and self.organization_id != self._loaded_organization_id:
            msg = f"The organization of an existing {type(self).__name__} cannot be changed."
            raise TenantReassignmentError(msg)
        super().save(*args, **kwargs)
        self._loaded_organization_id = self.organization_id
