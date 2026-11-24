"""Organizations and memberships (Batch 4; ADR-0003, ADR-0005, ADR-0015).

Users are global (``accounts.User``). A user's relationship to an organization is a
:class:`Membership`, which is tenant-owned. Its roles are ``rbac.MembershipRole`` rows (Batch 6);
invitations arrive in Batch 7.
"""

from typing import Any, ClassVar

from django.conf import settings
from django.db import models
from django.utils import timezone

from apps.core.models import BaseModel

from .tenancy import TenantScopedModel
from .validators import (
    SLUG_MAX_LENGTH,
    SLUG_PATTERN,
    normalize_slug,
    validate_slug,
    validate_timezone,
)

ORGANIZATION_SLUG_UNIQUE = "organizations_org_slug_uniq"
MEMBERSHIP_UNIQUE = "organizations_membership_org_user_uniq"


class OrganizationType(models.TextChoices):
    SCHOOL = "school", "School"
    UNIVERSITY = "university", "University"
    TRAINING = "training", "Training provider"
    OTHER = "other", "Other"


class OrganizationStatus(models.TextChoices):
    """Lifecycle (ADR-0005 clarifications, ADR-0015).

    ``provisioning`` → ``active`` happens only when the initial Owner invitation is accepted
    (Batch 7). ``suspended`` → ``active`` requires a verified active Owner (Batches 6/7). Neither
    transition exists in Batch 4, so no organization can become active without an Owner.
    """

    PROVISIONING = "provisioning", "Provisioning"
    ACTIVE = "active", "Active"
    SUSPENDED = "suspended", "Suspended"


class Organization(BaseModel):
    """A tenant. Not itself tenant-scoped: tenant data hangs off it."""

    name = models.CharField(max_length=200)
    slug = models.CharField(max_length=SLUG_MAX_LENGTH, validators=[validate_slug])
    organization_type = models.CharField(max_length=16, choices=OrganizationType.choices)
    status = models.CharField(
        max_length=16,
        choices=OrganizationStatus.choices,
        default=OrganizationStatus.PROVISIONING,
    )
    timezone = models.CharField(max_length=64, default="UTC", validators=[validate_timezone])
    # Users are deactivated, never deleted, so PROTECT keeps the creator accountable.
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+"
    )

    class Meta:
        constraints: ClassVar[list[Any]] = [
            models.UniqueConstraint(fields=["slug"], name=ORGANIZATION_SLUG_UNIQUE),
            models.CheckConstraint(
                condition=models.Q(slug__regex=SLUG_PATTERN), name="organizations_org_slug_format"
            ),
            models.CheckConstraint(
                condition=~models.Q(name=""), name="organizations_org_name_not_blank"
            ),
            models.CheckConstraint(
                condition=models.Q(organization_type__in=OrganizationType.values),
                name="organizations_org_type_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(status__in=OrganizationStatus.values),
                name="organizations_org_status_valid",
            ),
        ]
        indexes: ClassVar[list[Any]] = [
            models.Index(fields=["status", "name"], name="orgs_org_status_name_idx"),
        ]

    def __str__(self) -> str:
        return self.slug

    def clean_fields(self, exclude: Any = None) -> None:
        self.name = (self.name or "").strip()
        self.slug = normalize_slug(self.slug)
        super().clean_fields(exclude=exclude)

    @property
    def is_active(self) -> bool:
        return self.status == OrganizationStatus.ACTIVE


class MembershipStatus(models.TextChoices):
    ACTIVE = "active", "Active"
    SUSPENDED = "suspended", "Suspended"


class Membership(TenantScopedModel):
    """A global user's membership in one organization (tenant-owned)."""

    # PROTECT: removing a member is a service operation (Batch 6, ownership invariant), never a
    # side effect of deleting a user row.
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="memberships"
    )
    status = models.CharField(
        max_length=16, choices=MembershipStatus.choices, default=MembershipStatus.ACTIVE
    )
    joined_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints: ClassVar[list[Any]] = [
            models.UniqueConstraint(fields=["organization", "user"], name=MEMBERSHIP_UNIQUE),
            # Target of the composite foreign key from rbac.MembershipRole (Batch 6): a role
            # assignment must reference a membership of its own organization.
            models.UniqueConstraint(
                fields=["id", "organization"], name="organizations_membership_id_org_uniq"
            ),
            models.CheckConstraint(
                condition=models.Q(status__in=MembershipStatus.values),
                name="organizations_membership_status_valid",
            ),
        ]
        indexes: ClassVar[list[Any]] = [
            models.Index(fields=["user", "status"], name="orgs_membership_user_status"),
        ]

    def __str__(self) -> str:
        return f"Membership {self.id}"
