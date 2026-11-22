"""Reusable abstract base models.

All models exposed outside the system use UUIDv4 primary keys (non-enumerable, safe in URLs) and
timezone-aware creation/modification timestamps (``USE_TZ=True``; values are stored in UTC).

These classes are abstract: they create no tables or migrations by themselves.

Tenant scoping
--------------
Organization-owned models inherit ``apps.organizations.tenancy.TenantScopedModel`` (built on
:class:`BaseModel`). It lives in the ``organizations`` app because it references the concrete
``Organization`` model; ``core`` stays free of domain dependencies (ADR-0015).
"""

import uuid

from django.db import models


class UUIDModel(models.Model):
    """Primary key is a random UUID (version 4), generated in Python before insert."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        abstract = True


class CreatedAtModel(models.Model):
    """Records when the row was created (timezone-aware, set once on insert)."""

    created_at = models.DateTimeField(auto_now_add=True, editable=False, db_index=True)

    class Meta:
        abstract = True


class TimeStampedModel(CreatedAtModel):
    """Records creation and last-modification times (both timezone-aware).

    ``updated_at`` is refreshed by ``Model.save()``. Bulk ``QuerySet.update()`` bypasses
    ``auto_now``; services performing bulk updates must set ``updated_at`` explicitly.
    """

    updated_at = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        abstract = True


class BaseModel(UUIDModel, TimeStampedModel):
    """Default base for AEMS domain models: UUIDv4 primary key plus timestamps."""

    class Meta:
        abstract = True
