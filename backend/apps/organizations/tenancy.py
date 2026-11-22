"""Tenant-scoping foundation for organization-owned models (ADR-0003, ADR-0015).

Every tenant-owned model inherits :class:`TenantScopedModel`:

- ``organization`` is a non-null, indexed foreign key (``PROTECT``). It is not editable through
  model forms or ``ModelSerializer`` (``editable=False``), and it cannot change after creation.
  No reassignment service exists; adding one requires its own reviewed, explicitly named code
  path.
- Queries for tenant data go through ``Model.objects.for_organization(org)``, which **fails
  closed**: without a saved :class:`~apps.organizations.models.Organization` it raises
  :class:`MissingTenantContextError` instead of returning unscoped rows.
- Tenant API views obtain querysets only from ``OrganizationScopedViewMixin.get_scoped_queryset()``
  (enforced by the route-coverage meta-test).

Tenant immutability: application-level enforcement
--------------------------------------------------
These ORM write paths refuse to change the organization of an existing row
(:class:`TenantReassignmentError`), and a rejected operation writes nothing:

- ``Model.save()``, including ``update_fields``, ``force_update``, ``update_or_create()`` and rows
  loaded with ``only()``/``defer()`` (see :meth:`TenantScopedModel.save`);
- ``QuerySet.update()`` and ``bulk_update()`` naming ``organization`` or ``organization_id``;
- ``QuerySet.bulk_create(update_conflicts=True, update_fields=[...])`` naming either field
  (AEMS-012). Plain inserts and conflict updates of other fields are unaffected.

These checks are **not** database-enforced. Operations that bypass the model layer are outside
them and must not be used to write tenant rows without review:

- raw SQL (``connection.cursor()``, ``QuerySet.raw()``) and database clients;
- data migrations, which use historical models without these methods;
- ``loaddata``/deserialization, which saves with ``raw=True`` through ``save_base()``;
- Django internals called directly (``QuerySet._update()``, ``Model._do_update()``).

A database trigger or row-level security (ADR-0003, Phase 2) would be needed for database-level
immutability.

The default manager still returns all rows, because Django internals (admin, migrations, related
lookups, deletion collectors) require it. Cross-tenant reads are confined to named selectors
(``apps.organizations.selectors``), each documented as a narrow bypass. These are the paths that
PostgreSQL row-level security (Phase 2, ADR-0003) would have to allow explicitly.
"""

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, Self

from django.db import models

from apps.core.models import BaseModel

if TYPE_CHECKING:
    from .models import Organization

TENANT_FIELD = "organization"
TENANT_ATTNAME = f"{TENANT_FIELD}_id"
_TENANT_FIELDS = frozenset({TENANT_FIELD, TENANT_ATTNAME})


class _Unknown:
    """The organization id a row was loaded with is not known (field deferred or never loaded)."""

    def __repr__(self) -> str:
        return "<unknown>"


UNKNOWN = _Unknown()


class MissingTenantContextError(RuntimeError):
    """A tenant query or write was attempted without a resolved organization."""


class TenantReassignmentError(RuntimeError):
    """An ordinary update tried to move a tenant-owned row to another organization."""


def _names_tenant_field(fields: Iterable[str] | None) -> bool:
    return fields is not None and bool(_TENANT_FIELDS & set(fields))


class TenantQuerySet(models.QuerySet[Any]):
    def for_organization(self, organization: "Organization | None") -> Self:
        """Rows of one organization. Raises if the organization is missing or unsaved."""
        state = getattr(organization, "_state", None)
        if organization is None or state is None or state.adding:
            msg = "Tenant queries require a resolved organization."
            raise MissingTenantContextError(msg)
        return self.filter(**{TENANT_FIELD: organization})

    def update(self, **kwargs: Any) -> int:
        if _names_tenant_field(kwargs):
            msg = "The organization of tenant-owned rows cannot be changed by update()."
            raise TenantReassignmentError(msg)
        return super().update(**kwargs)

    def bulk_update(self, objs: Any, fields: Any, batch_size: int | None = None) -> int:
        if _names_tenant_field(fields):
            msg = "The organization of tenant-owned rows cannot be changed by bulk_update()."
            raise TenantReassignmentError(msg)
        return super().bulk_update(objs, fields, batch_size=batch_size)

    def bulk_create(self, objs: Any, *args: Any, **kwargs: Any) -> list[Any]:
        # A conflict update (upsert) rewrites the listed columns of the *existing* row, so it could
        # move another tenant's row. Refuse before any query runs. Positional arguments follow
        # QuerySet.bulk_create(objs, batch_size, ignore_conflicts, update_conflicts, update_fields).
        update_conflicts = kwargs.get("update_conflicts", args[2] if len(args) > 2 else False)  # noqa: PLR2004
        update_fields = kwargs.get("update_fields", args[3] if len(args) > 3 else None)  # noqa: PLR2004
        if update_conflicts and _names_tenant_field(update_fields):
            msg = "bulk_create() conflict updates cannot change the organization of existing rows."
            raise TenantReassignmentError(msg)
        return super().bulk_create(objs, *args, **kwargs)


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

    # The organization id this instance was loaded with (UNKNOWN if deferred or never loaded).
    _loaded_organization_id: Any = UNKNOWN

    class Meta:
        abstract = True

    @classmethod
    def from_db(cls, db: str | None, field_names: Any, values: Any) -> Self:
        instance = super().from_db(db, field_names, values)
        # A deferred field is absent from __dict__; never read it here (that would query).
        instance._loaded_organization_id = instance.__dict__.get(TENANT_ATTNAME, UNKNOWN)
        return instance

    def refresh_from_db(
        self, using: str | None = None, fields: Any = None, from_queryset: Any = None
    ) -> None:
        super().refresh_from_db(using=using, fields=fields, from_queryset=from_queryset)
        # Only a refresh that actually reloaded the organization (including the lazy load of a
        # deferred field) may update the baseline. A refresh of other fields must not turn an
        # in-memory reassignment into the "original" value.
        reloaded = fields is None or _names_tenant_field(fields)
        if reloaded and TENANT_ATTNAME in self.__dict__:
            self._loaded_organization_id = self.__dict__[TENANT_ATTNAME]

    def save(self, *args: Any, **kwargs: Any) -> None:
        force_update = bool(kwargs.get("force_update") or (len(args) > 1 and args[1]))
        update_fields = kwargs.get("update_fields", args[3] if len(args) > 3 else None)  # noqa: PLR2004
        updating = force_update or not self._state.adding

        if not updating:
            if self.__dict__.get(TENANT_ATTNAME) is None:
                msg = f"{type(self).__name__} requires an organization."
                raise MissingTenantContextError(msg)
        elif self._writes_organization(update_fields):
            self._check_not_reassigned()

        super().save(*args, **kwargs)
        if TENANT_ATTNAME in self.__dict__:
            self._loaded_organization_id = self.__dict__[TENANT_ATTNAME]

    def _writes_organization(self, update_fields: Iterable[str] | None) -> bool:
        if update_fields is not None:
            return _names_tenant_field(update_fields)
        # Django leaves deferred (never loaded, never assigned) fields out of the UPDATE.
        return TENANT_ATTNAME in self.__dict__

    def _check_not_reassigned(self) -> None:
        current = self.__dict__.get(TENANT_ATTNAME)
        if current is None:
            msg = f"{type(self).__name__} requires an organization."
            raise MissingTenantContextError(msg)
        original = self._loaded_organization_id
        if original is UNKNOWN:
            # Only for instances whose stored organization was never loaded, e.g. a forced update
            # of an instance built in memory: one query for the stored value.
            original = (
                type(self)
                ._base_manager.filter(pk=self.pk)
                .values_list(TENANT_ATTNAME, flat=True)
                .first()
            )
        if original is not None and current != original:
            msg = f"The organization of an existing {type(self).__name__} cannot be changed."
            raise TenantReassignmentError(msg)
