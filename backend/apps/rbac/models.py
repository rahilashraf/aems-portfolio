"""Organization-scoped RBAC models (Batch 6; ADR-0005, ADR-0017).

- :class:`Permission`: the synced, code-defined catalog (global, not tenant data).
- :class:`Role`: one organization's role. Three system roles (Owner, Admin, Member) are seeded
  per organization; others are custom.
- :class:`MembershipRole`: a role held by a membership. Both must belong to the same
  organization, enforced in the model and by composite foreign keys in the database
  (``rbac.0002``), so a cross-tenant assignment cannot be stored even through the ORM.

Django's global ``auth.Group``/``auth.Permission`` are not used for tenant authorization: they
remain platform (staff) permissions only.
"""

from typing import Any, ClassVar

from django.conf import settings
from django.db import models
from django.db.models.functions import Lower
from django.utils import timezone

from apps.organizations.models import Membership
from apps.organizations.tenancy import TenantScopedModel

from .registry import CODE_PATTERN

ROLE_NAME_UNIQUE = "rbac_role_org_name_ci_uniq"
ROLE_SYSTEM_KEY_UNIQUE = "rbac_role_org_system_key_uniq"
MEMBERSHIP_ROLE_UNIQUE = "rbac_membershiprole_membership_role_uniq"


class CrossTenantAssignmentError(ValueError):
    """A membership and a role of different organizations were combined."""


class Permission(models.Model):
    """One catalog entry. ``code`` is unique and never changes (database trigger, ``rbac.0002``)."""

    id = models.BigAutoField(primary_key=True)
    code = models.CharField(max_length=100, unique=True, editable=False)
    description = models.CharField(max_length=255)
    category = models.CharField(max_length=50)
    is_deprecated = models.BooleanField(default=False)

    class Meta:
        ordering = ("code",)
        constraints: ClassVar[list[Any]] = [
            models.CheckConstraint(
                condition=models.Q(code__regex=CODE_PATTERN), name="rbac_permission_code_format"
            ),
        ]

    def __str__(self) -> str:
        return self.code


class SystemRole(models.TextChoices):
    OWNER = "owner", "Owner"
    ADMIN = "admin", "Admin"
    MEMBER = "member", "Member"


class Role(TenantScopedModel):
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=255, blank=True, default="")
    is_system = models.BooleanField(default=False)
    # NULL (not "") marks a custom role: the partial unique constraint covers non-null keys only.
    system_key = models.CharField(  # noqa: DJ001
        max_length=16, choices=SystemRole.choices, null=True, blank=True, editable=False
    )
    permissions = models.ManyToManyField(Permission, related_name="roles", blank=True)

    class Meta:
        constraints: ClassVar[list[Any]] = [
            models.UniqueConstraint("organization", Lower("name"), name=ROLE_NAME_UNIQUE),
            models.UniqueConstraint(
                fields=["organization", "system_key"],
                condition=models.Q(system_key__isnull=False),
                name=ROLE_SYSTEM_KEY_UNIQUE,
            ),
            # Target of the composite foreign key from MembershipRole (same organization).
            models.UniqueConstraint(fields=["id", "organization"], name="rbac_role_id_org_uniq"),
            models.CheckConstraint(
                condition=models.Q(system_key__isnull=True)
                | models.Q(system_key__in=SystemRole.values),
                name="rbac_role_system_key_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(is_system=True, system_key__isnull=False)
                | models.Q(is_system=False, system_key__isnull=True),
                name="rbac_role_system_flag_matches_key",
            ),
            models.CheckConstraint(condition=~models.Q(name=""), name="rbac_role_name_not_blank"),
        ]

    def __str__(self) -> str:
        return self.name

    @property
    def is_owner(self) -> bool:
        return self.system_key == SystemRole.OWNER


class MembershipRole(TenantScopedModel):
    """A role held by a membership, in the membership's own organization."""

    # Indexed by the (membership, role) unique constraint.
    membership = models.ForeignKey(
        Membership, on_delete=models.CASCADE, related_name="role_links", db_index=False
    )
    # PROTECT: a role that is still assigned cannot be deleted (rbac.services.delete_role).
    role = models.ForeignKey(Role, on_delete=models.PROTECT, related_name="assignments")
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, related_name="+"
    )
    assigned_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints: ClassVar[list[Any]] = [
            models.UniqueConstraint(fields=["membership", "role"], name=MEMBERSHIP_ROLE_UNIQUE),
        ]

    def __str__(self) -> str:
        return f"MembershipRole {self.pk}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        self.check_same_organization()
        super().save(*args, **kwargs)

    def check_same_organization(self) -> None:
        membership_org = Membership.objects.filter(pk=self.membership_id).values_list(
            "organization_id", flat=True
        )
        role_org = Role.objects.filter(pk=self.role_id).values_list("organization_id", flat=True)
        organizations = {self.organization_id, *membership_org, *role_org}
        if len(organizations) != 1:
            msg = "A membership can only hold roles of its own organization."
            raise CrossTenantAssignmentError(msg)
