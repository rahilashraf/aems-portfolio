"""Organizations and memberships (Batch 4; ADR-0003, ADR-0005, ADR-0015).

Users are global (``accounts.User``). A user's relationship to an organization is a
:class:`Membership`, which is tenant-owned. Its roles are ``rbac.MembershipRole`` rows (Batch 6);
invitations (Batch 7) are :class:`Invitation` rows.
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
    """Lifecycle (ADR-0005 clarifications, ADR-0015, ADR-0018).

    ``provisioning`` → ``active`` happens only inside the transaction that accepts the initial
    Owner invitation (``organizations.invitations.accept_invitation``), which creates the Owner
    membership first. ``suspended`` → ``active`` is not available (it would need an approved,
    Owner-verified reactivation path). So no organization can become active without an Owner.
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
        permissions: ClassVar[list[tuple[str, Any]]] = [
            (
                "manage_initial_owner_invitation",
                "Can issue, reissue and revoke the initial Owner invitation",
            ),
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


# ------------------------------------------------------------------------------ invitations
INVITATION_PENDING_UNIQUE = "organizations_invitation_one_pending_per_email"
INVITATION_DIGEST_UNIQUE = "organizations_invitation_token_hash_uniq"


class InvitationStatus(models.TextChoices):
    """Lifecycle (ADR-0018). Only ``pending`` can change; the others are terminal.

    A database trigger (``organizations.0004``) makes terminal rows immutable, so an invitation
    can be accepted at most once and an accepted invitation can never be revoked or reopened.
    """

    PENDING = "pending", "Pending"
    ACCEPTED = "accepted", "Accepted"
    REVOKED = "revoked", "Revoked"
    EXPIRED = "expired", "Expired"


class Invitation(TenantScopedModel):
    """An invitation to join one organization with a set of that organization's roles.

    ``token_hash`` is the SHA-256 digest of the 256-bit token in the most recently delivered
    email; it stays empty until the delivery command sends the first email. The raw token is never
    stored. ``is_initial_owner`` marks the invitation created with a provisioning organization: it
    grants only the Owner role, and its acceptance is the only path from ``provisioning`` to
    ``active``.
    """

    email = models.EmailField(max_length=254)
    is_initial_owner = models.BooleanField(default=False)
    status = models.CharField(
        max_length=16, choices=InvitationStatus.choices, default=InvitationStatus.PENDING
    )
    roles: "models.ManyToManyField[Any, Any]" = models.ManyToManyField(
        "rbac.Role", through="InvitationRole", related_name="+"
    )
    token_hash = models.CharField(max_length=64, null=True, blank=True, editable=False)  # noqa: DJ001
    token_issued_at = models.DateTimeField(null=True, blank=True, editable=False)
    # PROTECT: users are deactivated, never deleted, so the inviter stays accountable.
    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+"
    )
    expires_at = models.DateTimeField()
    accepted_at = models.DateTimeField(null=True, blank=True)
    accepted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True, related_name="+"
    )
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True, related_name="+"
    )

    class Meta:
        constraints: ClassVar[list[Any]] = [
            # One pending invitation per address and organization.
            models.UniqueConstraint(
                fields=["organization", "email"],
                condition=models.Q(status=InvitationStatus.PENDING),
                name=INVITATION_PENDING_UNIQUE,
            ),
            # One pending initial-Owner invitation per organization (reissue revokes the old one).
            models.UniqueConstraint(
                fields=["organization"],
                condition=models.Q(status=InvitationStatus.PENDING, is_initial_owner=True),
                name="organizations_invitation_one_pending_initial_owner",
            ),
            models.UniqueConstraint(
                fields=["token_hash"],
                condition=models.Q(token_hash__isnull=False),
                name=INVITATION_DIGEST_UNIQUE,
            ),
            # Target of the composite foreign key from InvitationRole (same organization).
            models.UniqueConstraint(
                fields=["id", "organization"], name="organizations_invitation_id_org_uniq"
            ),
            models.CheckConstraint(
                condition=models.Q(email=models.functions.Lower("email")) & ~models.Q(email=""),
                name="organizations_invitation_email_normalized",
            ),
            models.CheckConstraint(
                condition=models.Q(status__in=InvitationStatus.values),
                name="organizations_invitation_status_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(token_hash__isnull=True)
                # Tuple form: a lowercase SHA-256 hex digest (64 characters).
                | models.Q(("token_hash__regex", r"^[0-9a-f]{64}$")),
                name="organizations_invitation_token_hash_format",
            ),
            models.CheckConstraint(
                condition=models.Q(expires_at__gt=models.F("created_at")),
                name="organizations_invitation_expiry_after_creation",
            ),
            # The timestamps and actors always agree with the status.
            models.CheckConstraint(
                condition=(
                    models.Q(
                        status=InvitationStatus.PENDING,
                        accepted_at__isnull=True,
                        accepted_by__isnull=True,
                        revoked_at__isnull=True,
                    )
                    | models.Q(
                        status=InvitationStatus.ACCEPTED,
                        accepted_at__isnull=False,
                        accepted_by__isnull=False,
                        revoked_at__isnull=True,
                        accepted_at__lt=models.F("expires_at"),
                    )
                    | models.Q(
                        status=InvitationStatus.REVOKED,
                        revoked_at__isnull=False,
                        accepted_at__isnull=True,
                        accepted_by__isnull=True,
                    )
                    | models.Q(
                        status=InvitationStatus.EXPIRED,
                        accepted_at__isnull=True,
                        accepted_by__isnull=True,
                        revoked_at__isnull=True,
                    )
                ),
                name="organizations_invitation_state_consistent",
            ),
        ]
        indexes: ClassVar[list[Any]] = [
            models.Index(
                fields=["organization", "status", "created_at"], name="orgs_invitation_org_status"
            ),
        ]

    def __str__(self) -> str:
        return f"Invitation {self.id}"


class InvitationRole(TenantScopedModel):
    """A role an invitation grants, in the invitation's own organization.

    Composite foreign keys (``organizations.0004``) bind both the invitation and the role to
    ``organization_id``, so a cross-tenant role cannot be attached even with raw SQL.
    """

    invitation = models.ForeignKey(
        Invitation, on_delete=models.CASCADE, related_name="role_links", db_index=False
    )
    # CASCADE only matters for historical (non-pending) invitations: rbac.services.delete_role
    # refuses to delete a role that a pending invitation would grant.
    role = models.ForeignKey("rbac.Role", on_delete=models.CASCADE, related_name="+")

    class Meta:
        constraints: ClassVar[list[Any]] = [
            models.UniqueConstraint(
                fields=["invitation", "role"], name="organizations_invitationrole_uniq"
            ),
        ]

    def __str__(self) -> str:
        return f"InvitationRole {self.pk}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        from apps.rbac.models import Role  # noqa: PLC0415 - rbac imports this module

        invitation_org = Invitation.objects.filter(pk=self.invitation_id).values_list(
            "organization_id", flat=True
        )
        role_org = Role.objects.filter(pk=self.role_id).values_list("organization_id", flat=True)
        if len({self.organization_id, *invitation_org, *role_org}) != 1:
            msg = "An invitation can only grant roles of its own organization."
            raise ValueError(msg)
        super().save(*args, **kwargs)


class InvitationEmailStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    DELIVERED = "delivered", "Delivered"
    FAILED = "failed", "Failed"
    CANCELLED = "cancelled", "Cancelled"


class InvitationEmail(BaseModel):
    """Outbox row: "send the email for this invitation" (ADR-0018, modelled on ADR-0014).

    It holds no address, token, link or message body: the delivery command reads the invitation's
    address and issues a fresh token when it sends. Not a general job queue.
    """

    invitation = models.OneToOneField(
        Invitation, on_delete=models.CASCADE, related_name="email_delivery"
    )
    status = models.CharField(
        max_length=16, choices=InvitationEmailStatus.choices, default=InvitationEmailStatus.PENDING
    )
    attempts = models.PositiveIntegerField(default=0)
    next_attempt_at = models.DateTimeField(default=timezone.now)
    claim_id = models.UUIDField(null=True, blank=True)
    claimed_until = models.DateTimeField(null=True, blank=True)
    last_attempt_at = models.DateTimeField(null=True, blank=True)
    last_failure = models.CharField(max_length=32, blank=True, default="")
    delivered_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints: ClassVar[list[Any]] = [
            models.CheckConstraint(
                condition=models.Q(status__in=InvitationEmailStatus.values),
                name="organizations_invitationemail_status_valid",
            ),
        ]
        indexes: ClassVar[list[Any]] = [
            models.Index(
                fields=["next_attempt_at"],
                condition=models.Q(status=InvitationEmailStatus.PENDING),
                name="orgs_invitationemail_due",
            ),
        ]

    def __str__(self) -> str:
        return f"InvitationEmail {self.pk}"
