"""The audit log (ADR-0006, ADR-0016).

``AuditLog`` is **append-only**:

- the model refuses ``save()`` of an existing row and ``delete()``;
- the queryset refuses ``update()``, ``delete()``, ``bulk_update()`` and conflict-updating
  ``bulk_create()``;
- a PostgreSQL trigger rejects ``UPDATE`` and ``DELETE`` on the table (migration ``0002``);
- the runtime database role holds only ``SELECT`` and ``INSERT`` on it and does not own it
  (:mod:`apps.audit.privileges`).

It is **not** a ``TenantScopedModel``: ``organization`` is deliberately nullable for platform and
account events. Tenant reads must use :meth:`AuditLogQuerySet.for_organization`, which fails closed,
and platform reads :meth:`AuditLogQuerySet.platform_events`, which returns only rows without an
organization. Rows are written only by :mod:`apps.audit.services`.
"""

import uuid
from typing import TYPE_CHECKING, Any, ClassVar, Self

from django.conf import settings
from django.db import models
from django.utils import timezone

if TYPE_CHECKING:
    from apps.organizations.models import Organization

ACTION_PATTERN = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$"
TARGET_TYPE_PATTERN = r"^[a-z][a-z0-9_]*$"


class AuditLogImmutableError(RuntimeError):
    """An attempt to change or delete an audit record."""


class MissingAuditScopeError(RuntimeError):
    """A tenant audit query was attempted without a resolved organization."""


class AuditOutcome(models.TextChoices):
    SUCCESS = "success", "Success"
    FAILURE = "failure", "Failure"


def _immutable(operation: str) -> AuditLogImmutableError:
    return AuditLogImmutableError(f"Audit records are append-only: {operation} is not allowed.")


class AuditLogQuerySet(models.QuerySet["AuditLog"]):
    def for_organization(self, organization: "Organization | None") -> Self:
        """Events of one organization. Raises if the organization is missing or unsaved."""
        state = getattr(organization, "_state", None)
        if organization is None or state is None or state.adding:
            msg = "Tenant audit queries require a resolved organization."
            raise MissingAuditScopeError(msg)
        return self.filter(organization=organization)

    def platform_events(self) -> Self:
        """Events that belong to no organization (accounts, platform, tenant-access denials)."""
        return self.filter(organization__isnull=True)

    def update(self, **kwargs: Any) -> int:
        raise _immutable("update()")

    def delete(self) -> tuple[int, dict[str, int]]:
        raise _immutable("delete()")

    def bulk_update(self, objs: Any, fields: Any, batch_size: int | None = None) -> int:
        raise _immutable("bulk_update()")

    def bulk_create(self, objs: Any, *args: Any, **kwargs: Any) -> list[Any]:
        # Rows are written one at a time by the audit service; a bulk upsert could rewrite history.
        raise _immutable("bulk_create()")


AuditLogManager = models.Manager.from_queryset(AuditLogQuerySet)


class AuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # PROTECT: organizations and users are deactivated, never deleted; history must survive.
    # Single-column indexes are omitted: the composite indexes below lead with these columns.
    organization = models.ForeignKey(
        "organizations.Organization",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="+",
        db_index=False,
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="+",
        db_index=False,
    )
    actor_email = models.EmailField(max_length=254, blank=True, default="")
    action = models.CharField(max_length=100)
    outcome = models.CharField(max_length=16, choices=AuditOutcome.choices)
    target_type = models.CharField(max_length=64, blank=True, default="")
    target_id = models.CharField(max_length=64, blank=True, default="")
    changes = models.JSONField(default=dict, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=256, blank=True, default="")
    request_id = models.CharField(max_length=128, blank=True, default="")
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    objects = AuditLogManager()

    class Meta:
        constraints: ClassVar[list[Any]] = [
            models.CheckConstraint(
                condition=models.Q(action__regex=ACTION_PATTERN),
                name="audit_auditlog_action_format",
            ),
            models.CheckConstraint(
                condition=models.Q(outcome__in=AuditOutcome.values),
                name="audit_auditlog_outcome_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(target_type="")
                | models.Q(target_type__regex=TARGET_TYPE_PATTERN),
                name="audit_auditlog_target_type_format",
            ),
        ]
        indexes: ClassVar[list[Any]] = [
            models.Index(fields=["organization", "created_at"], name="audit_org_created_idx"),
            models.Index(fields=["action", "created_at"], name="audit_action_created_idx"),
            models.Index(fields=["actor", "created_at"], name="audit_actor_created_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.action} ({self.outcome}) {self.id}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding or kwargs.get("force_update") or kwargs.get("update_fields"):
            raise _immutable("save() of an existing record")
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise _immutable("delete()")
