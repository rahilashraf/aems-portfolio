"""Organization writes: creation and lifecycle (ADR-0005, ADR-0015).

Rules enforced here, not in views:

- Platform administrators create organizations; every new organization starts ``provisioning``.
- **No service activates an organization.** ``provisioning → active`` belongs to the Owner
  invitation acceptance (Batch 7), and ``suspended → active`` requires a verified active Owner
  (Batches 6/7). Both are rejected here.
- ``active → suspended`` is allowed and takes effect immediately: tenant access is checked on
  every request.
- ``id``, ``slug``, ``created_by`` and timestamps cannot be changed.

Mutations lock the organization row and write their audit records inside the same transaction
(ADR-0016): the change and its record commit or roll back together.
"""

from typing import Any

from django.db import IntegrityError, transaction

from apps.audit import services as audit
from apps.rbac import services as rbac

from . import invitations
from .exceptions import OrganizationSlugTakenError, OrganizationStatusTransitionError
from .models import ORGANIZATION_SLUG_UNIQUE, Organization, OrganizationStatus

# Fields a platform administrator may change after creation (status has its own rules).
PLATFORM_EDITABLE_FIELDS = frozenset({"name", "organization_type", "timezone", "status"})
# Fields an organization may change about itself (Batch 6: requires "organization.update").
TENANT_EDITABLE_FIELDS = frozenset({"name", "timezone"})

ALLOWED_STATUS_TRANSITIONS: frozenset[tuple[str, str]] = frozenset(
    {(OrganizationStatus.ACTIVE, OrganizationStatus.SUSPENDED)}
)


def _is_slug_violation(exc: IntegrityError) -> bool:
    diag = getattr(exc.__cause__, "diag", None)
    return getattr(diag, "constraint_name", None) == ORGANIZATION_SLUG_UNIQUE


def create_organization(
    *,
    actor: Any,
    name: str,
    slug: str,
    organization_type: str,
    initial_owner_email: str,
    timezone: str = "UTC",
    client_ip: str | None = None,
) -> Organization:
    """Create a ``provisioning`` organization, its system roles and its initial Owner invitation.

    One transaction: if seeding, the invitation, its email outbox row or an audit record fails,
    nothing is created. The creator does not become a member, and the organization stays
    ``provisioning`` until the invitation is accepted (ADR-0018).
    """
    organization = Organization(
        name=name,
        slug=slug,
        organization_type=organization_type,
        timezone=timezone,
        status=OrganizationStatus.PROVISIONING,
        created_by=actor,
    )
    organization.full_clean(validate_unique=False, validate_constraints=False)
    try:
        with transaction.atomic():
            organization.save(force_insert=True)
            # Role definitions only: nobody becomes an Owner and the status stays provisioning.
            rbac.seed_system_roles(organization)
            audit.record(
                "organization.created",
                actor=actor,
                organization=organization,
                target_type="organization",
                target_id=organization.pk,
                client_ip=client_ip,
                metadata={"status": organization.status},
            )
            invitations.issue_initial_owner_invitation(
                actor=actor,
                organization=organization,
                email=initial_owner_email,
                client_ip=client_ip,
            )
    except IntegrityError as exc:
        if _is_slug_violation(exc):
            raise OrganizationSlugTakenError() from exc
        raise
    return organization


def _apply_changes(
    organization: Organization, changes: dict[str, Any], allowed: frozenset[str]
) -> dict[str, tuple[Any, Any]]:
    """Apply allowed changes; return ``{field: (before, after)}`` for the fields that changed."""
    unexpected = set(changes) - allowed
    if unexpected:
        msg = f"Fields not editable here: {', '.join(sorted(unexpected))}"
        raise ValueError(msg)
    changed = {
        field: (getattr(organization, field), value)
        for field, value in changes.items()
        if getattr(organization, field) != value
    }
    for field, (_before, after) in changed.items():
        setattr(organization, field, after)
    return changed


def update_organization(
    *, actor: Any, organization: Organization, changes: dict[str, Any], client_ip: str | None = None
) -> Organization:
    """Platform administration update (``PATCH /platform/organizations/{id}/``)."""
    with transaction.atomic():
        locked = Organization.objects.select_for_update().get(pk=organization.pk)
        previous_status = locked.status
        new_status = changes.get("status", previous_status)
        if new_status != previous_status and (
            (previous_status, new_status) not in ALLOWED_STATUS_TRANSITIONS
        ):
            raise OrganizationStatusTransitionError()
        changed = _apply_changes(locked, changes, PLATFORM_EDITABLE_FIELDS)
        _save(locked, list(changed))
        if changed:
            audit.record(
                "organization.updated",
                actor=actor,
                organization=locked,
                target_type="organization",
                target_id=locked.pk,
                changes=changed,
                client_ip=client_ip,
            )
        if "status" in changed:
            audit.record(
                "organization.status_changed",
                actor=actor,
                organization=locked,
                target_type="organization",
                target_id=locked.pk,
                client_ip=client_ip,
                metadata={"previous_status": previous_status, "status": locked.status},
            )
    return locked


def update_organization_profile(
    *, actor: Any, organization: Organization, changes: dict[str, Any], client_ip: str | None = None
) -> Organization:
    """An organization editing its own profile (``PATCH /organizations/{org_id}/``).

    The actor's ``organization.update`` permission is re-checked from current database state
    after the organization row is locked, so a permission revoked while the request was in flight
    cannot be used (ADR-0017).
    """
    with transaction.atomic():
        locked = Organization.objects.select_for_update().get(pk=organization.pk)
        if locked.status != OrganizationStatus.ACTIVE:
            raise OrganizationStatusTransitionError()
        rbac.require_fresh_permission(locked, actor, "organization.update")
        changed = _apply_changes(locked, changes, TENANT_EDITABLE_FIELDS)
        _save(locked, list(changed))
        if changed:
            audit.record(
                "organization.profile_updated",
                actor=actor,
                organization=locked,
                target_type="organization",
                target_id=locked.pk,
                changes=changed,
                client_ip=client_ip,
            )
    return locked


def _save(organization: Organization, changed: list[str]) -> None:
    if not changed:
        return
    organization.full_clean(validate_unique=False, validate_constraints=False)
    organization.save(update_fields=[*changed, "updated_at"])
