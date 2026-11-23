"""Organization writes: creation and lifecycle (ADR-0005, ADR-0015).

Rules enforced here, not in views:

- Platform administrators create organizations; every new organization starts ``provisioning``.
- **No service activates an organization.** ``provisioning → active`` belongs to the Owner
  invitation acceptance (Batch 7), and ``suspended → active`` requires a verified active Owner
  (Batches 6/7). Both are rejected here.
- ``active → suspended`` is allowed and takes effect immediately: tenant access is checked on
  every request.
- ``id``, ``slug``, ``created_by`` and timestamps cannot be changed.

Mutations lock the organization row and emit their security events only after commit.
"""

from typing import Any

from django.db import IntegrityError, transaction

from apps.core.security_events import record_after_commit

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
    timezone: str = "UTC",
    client_ip: str | None = None,
) -> Organization:
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
            record_after_commit(
                "organization.created",
                user_id=actor.pk,
                client_ip=client_ip,
                organization_id=str(organization.pk),
                status=organization.status,
            )
    except IntegrityError as exc:
        if _is_slug_violation(exc):
            raise OrganizationSlugTakenError() from exc
        raise
    return organization


def _apply_changes(
    organization: Organization, changes: dict[str, Any], allowed: frozenset[str]
) -> list[str]:
    unexpected = set(changes) - allowed
    if unexpected:
        msg = f"Fields not editable here: {', '.join(sorted(unexpected))}"
        raise ValueError(msg)
    changed = [field for field, value in changes.items() if getattr(organization, field) != value]
    for field in changed:
        setattr(organization, field, changes[field])
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
        _save(locked, changed)
        if changed:
            record_after_commit(
                "organization.updated",
                user_id=actor.pk,
                client_ip=client_ip,
                organization_id=str(locked.pk),
                changed_fields=sorted(changed),
            )
        if "status" in changed:
            record_after_commit(
                "organization.status_changed",
                user_id=actor.pk,
                client_ip=client_ip,
                organization_id=str(locked.pk),
                previous_status=previous_status,
                status=locked.status,
            )
    return locked


def update_organization_profile(
    *, actor: Any, organization: Organization, changes: dict[str, Any], client_ip: str | None = None
) -> Organization:
    """An organization editing its own profile.

    Exposed at ``PATCH /organizations/{org_id}/`` only behind the ``organization.update``
    permission, which cannot be granted until Batch 6, so the endpoint currently fails closed.
    """
    with transaction.atomic():
        locked = Organization.objects.select_for_update().get(pk=organization.pk)
        if locked.status != OrganizationStatus.ACTIVE:
            raise OrganizationStatusTransitionError()
        changed = _apply_changes(locked, changes, TENANT_EDITABLE_FIELDS)
        _save(locked, changed)
        if changed:
            record_after_commit(
                "organization.profile_updated",
                user_id=actor.pk,
                client_ip=client_ip,
                organization_id=str(locked.pk),
                changed_fields=sorted(changed),
            )
    return locked


def _save(organization: Organization, changed: list[str]) -> None:
    if not changed:
        return
    organization.full_clean(validate_unique=False, validate_constraints=False)
    organization.save(update_fields=[*changed, "updated_at"])
