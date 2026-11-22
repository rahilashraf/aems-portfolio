"""Reusable abstract base models.

All models exposed outside the system use UUIDv4 primary keys (non-enumerable, safe in URLs) and
timezone-aware creation/modification timestamps (``USE_TZ=True``; values are stored in UTC).

These classes are abstract: they create no tables or migrations by themselves.

Tenant scoping (extension strategy, Batch 4)
--------------------------------------------
Organization-owned models will inherit a ``TenantScopedModel`` defined alongside the
``organizations`` app, built on top of :class:`BaseModel`::

    class TenantScopedModel(BaseModel):
        organization = models.ForeignKey("organizations.Organization", on_delete=models.PROTECT)
        objects = TenantQuerySet.as_manager()  # .for_organization(org)

        class Meta:
            abstract = True

It is deliberately not defined here yet: it requires the concrete ``Organization`` model, and
defining it early would create a dangling dependency from ``core`` on a domain app.
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
