"""RBAC mutations: roles, membership status, role assignment, ownership (plan §6, ADR-0017).

Every authorization-sensitive mutation follows one protocol, inside ``transaction.atomic()``:

1. Lock the **organization row** (``SELECT … FOR UPDATE``). All RBAC mutations of an
   organization, and global deactivations of its members, serialize on it.
2. Lock the actor's membership and the target memberships **in ascending id order**.
3. Re-load the actor's membership and effective permissions from current database state
   (:func:`apps.rbac.engine.fresh_permissions`) and re-check the required permission. The
   request-level check is only an early rejection; this one is authoritative.
4. Re-check the self-modification, delegation and Owner rules.
5. Re-count active Owners from current state and refuse a change that would leave an active
   organization without one (:class:`LastOwnerError`).
6. Apply the change and write its audit records in the same transaction.

**Lock order (deadlock freedom).** Locks are always taken in the order user row → organization
rows (ascending id) → membership rows (ascending id) → role rows. Membership and role operations
start at the organization and never lock user rows. Global deactivation
(:func:`assert_deactivation_keeps_owners`) holds the user row and then locks *every* organization
in which the user has a membership, in ascending id order. Because every operation that can make
someone an Owner, or remove an Owner, holds the organization lock, the set of organizations to
lock cannot grow while deactivation holds the user lock (new memberships, Batch 7, must lock the
user row before the organization).

**Rules.**

- No self-modification: an actor cannot change their own status, remove their own membership,
  or change their own roles. Exception: an Owner may give up the Owner role (and nothing else in
  the same request) while another active Owner remains.
- Delegation: an actor can only grant or remove permissions they hold, whether by editing a
  role's permissions, assigning or removing roles, or suspending, reactivating or removing a
  member. Editing a role the actor holds therefore cannot raise the actor's own permissions.
- Only Owners grant or revoke the Owner role, or change an Owner's membership.
- The Owner role is immutable; system roles cannot be renamed or deleted.
- Owners pass through the same checks; nothing short-circuits on "is owner" except the rules
  that require it. Platform staff status grants nothing here.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from django.db import IntegrityError, transaction
from rest_framework import exceptions

from apps.accounts.models import User
from apps.audit import services as audit
from apps.organizations.models import (
    Membership,
    MembershipStatus,
    Organization,
    OrganizationStatus,
)

from .catalog import ADMIN_DEFAULT_PERMISSIONS, MEMBER_DEFAULT_PERMISSIONS
from .engine import fresh_permissions
from .exceptions import (
    DelegationError,
    LastOwnerError,
    OwnerRoleRestrictedError,
    RbacForbiddenError,
    RoleInUseError,
    RoleNameTakenError,
    SelfModificationError,
    SystemRoleProtectedError,
    UnknownPermissionError,
)
from .models import ROLE_NAME_UNIQUE, MembershipRole, Permission, Role, SystemRole
from .registry import registry

SYSTEM_ROLE_DEFINITIONS: tuple[tuple[str, str, str, frozenset[str] | None], ...] = (
    (SystemRole.OWNER, "Owner", "Full control of the organization, including ownership.", None),
    (
        SystemRole.ADMIN,
        "Admin",
        "Manages the organization, its members and roles; cannot manage ownership.",
        ADMIN_DEFAULT_PERMISSIONS,
    ),
    (SystemRole.MEMBER, "Member", "Default role for members.", MEMBER_DEFAULT_PERMISSIONS),
)
ROLE_EDITABLE_FIELDS = frozenset({"name", "description", "permissions"})


# ------------------------------------------------------------------------------- seeding
def seed_system_roles(organization: Organization) -> list[Role]:
    """Create any missing system role of ``organization`` (idempotent).

    Must run inside the transaction that creates the organization. Existing roles are left as they
    are (their editable permissions are never reset). Seeding defines the Owner role; it does not
    make anyone an Owner and does not change the organization's status.
    """
    existing = {
        r.system_key: r
        for r in Role.objects.for_organization(organization).filter(system_key__isnull=False)
    }
    permissions = {p.code: p for p in Permission.objects.filter(is_deprecated=False)}
    roles = []
    for key, name, description, defaults in SYSTEM_ROLE_DEFINITIONS:
        role = existing.get(key)
        if role is None:
            role = Role(
                organization=organization,
                name=name,
                description=description,
                is_system=True,
                system_key=key,
            )
            role.save(force_insert=True)
            if defaults:
                role.permissions.set([permissions[c] for c in sorted(defaults) if c in permissions])
        roles.append(role)
    return roles


# -------------------------------------------------------------------------------- helpers
@dataclass(frozen=True)
class Actor:
    user: Any
    membership: Membership
    permissions: frozenset[str]
    is_owner: bool

    def require(self, *codes: str) -> None:
        if not set(codes) <= self.permissions:
            raise RbacForbiddenError()


def _lock_organization(organization: Organization) -> Organization:
    return Organization.objects.select_for_update().get(pk=organization.pk)


def _lock_actor_and_targets(
    organization: Organization, actor_user: Any, target_ids: Iterable[Any] = ()
) -> tuple[Actor, dict[Any, Membership]]:
    """Lock the actor's and the targets' memberships (ascending id); load fresh permissions."""
    actor_id = (
        Membership.objects.for_organization(organization)
        .filter(user_id=getattr(actor_user, "pk", None))
        .values_list("pk", flat=True)
        .first()
    )
    if actor_id is None:
        raise RbacForbiddenError()
    ids = {actor_id, *target_ids}
    locked = {
        m.pk: m
        for m in Membership.objects.for_organization(organization)
        .select_for_update()
        .filter(pk__in=ids)
        .order_by("pk")
    }
    permissions, is_owner = fresh_permissions(actor_id)
    if not permissions:
        # Inactive account, suspended membership or inactive organization: holds nothing.
        raise RbacForbiddenError()
    return Actor(actor_user, locked[actor_id], permissions, is_owner), locked


def _target(locked: dict[Any, Membership], membership_id: Any) -> Membership:
    try:
        return locked[membership_id]
    except KeyError:
        raise exceptions.NotFound() from None


def _role_ids(organization: Organization, membership: Membership) -> set[Any]:
    return set(
        MembershipRole.objects.for_organization(organization)
        .filter(membership=membership)
        .values_list("role_id", flat=True)
    )


def _authority(roles: Iterable[Role]) -> tuple[frozenset[str], bool]:
    """Permissions conferred by ``roles`` (active catalog codes) and whether one is Owner."""
    roles = list(roles)
    if any(r.is_owner for r in roles):
        return registry.active_codes(), True
    codes = set(
        Permission.objects.filter(roles__in=roles, is_deprecated=False).values_list(
            "code", flat=True
        )
    )
    return frozenset(c for c in codes if registry.is_active(c)), False


def _roles(organization: Organization, role_ids: Iterable[Any]) -> list[Role]:
    return list(Role.objects.for_organization(organization).filter(pk__in=set(role_ids)))


def _active_owner_ids(organization: Organization) -> set[Any]:
    """Memberships that are active Owners right now (active membership, active account)."""
    return set(
        MembershipRole.objects.for_organization(organization)
        .filter(
            role__system_key=SystemRole.OWNER,
            membership__status=MembershipStatus.ACTIVE,
            membership__user__is_active=True,
        )
        .values_list("membership_id", flat=True)
    )


def _ensure_owner_remains(organization: Organization, remaining: set[Any]) -> None:
    if organization.status == OrganizationStatus.ACTIVE and not remaining:
        raise LastOwnerError([organization.pk])


def _check_authority_over(
    organization: Organization, actor: Actor, target: Membership
) -> tuple[list[Role], bool]:
    """The actor may act on ``target`` only if they hold everything the target's roles confer."""
    roles = _roles(organization, _role_ids(organization, target))
    permissions, owner = _authority(roles)
    if owner and not actor.is_owner:
        raise OwnerRoleRestrictedError()
    if not permissions <= actor.permissions:
        raise DelegationError()
    return roles, owner


def _validated_codes(codes: Iterable[str]) -> set[str]:
    codes = set(codes)
    if registry.unknown_or_inactive(codes):
        raise UnknownPermissionError()
    return codes


# ---------------------------------------------------------------------- membership status
def update_membership_status(
    *,
    actor: Any,
    organization: Organization,
    membership_id: Any,
    status: str,
    client_ip: str | None = None,
) -> Membership:
    if status not in MembershipStatus.values:
        msg = f"Unknown membership status {status!r}."
        raise ValueError(msg)
    with transaction.atomic():
        locked_org = _lock_organization(organization)
        acting, locked = _lock_actor_and_targets(locked_org, actor, [membership_id])
        acting.require("members.manage")
        target = _target(locked, membership_id)
        if target.pk == acting.membership.pk:
            raise SelfModificationError()
        _check_authority_over(locked_org, acting, target)
        previous = target.status
        if previous == status:
            return target
        if status == MembershipStatus.SUSPENDED:
            _ensure_owner_remains(locked_org, _active_owner_ids(locked_org) - {target.pk})
        target.status = status
        target.save(update_fields=["status", "updated_at"])
        audit.record(
            "rbac.membership.status_changed",
            actor=actor,
            organization=locked_org,
            target_type="membership",
            target_id=target.pk,
            changes={"status": (previous, status)},
            client_ip=client_ip,
            metadata={"member_user_id": target.user_id},
        )
    return target


def remove_membership(
    *, actor: Any, organization: Organization, membership_id: Any, client_ip: str | None = None
) -> None:
    with transaction.atomic():
        locked_org = _lock_organization(organization)
        acting, locked = _lock_actor_and_targets(locked_org, actor, [membership_id])
        acting.require("members.manage")
        target = _target(locked, membership_id)
        if target.pk == acting.membership.pk:
            raise SelfModificationError()
        roles, _owner = _check_authority_over(locked_org, acting, target)
        _ensure_owner_remains(locked_org, _active_owner_ids(locked_org) - {target.pk})
        member_user_id = target.user_id
        target_id = target.pk
        MembershipRole.objects.for_organization(locked_org).filter(membership=target).delete()
        target.delete()
        audit.record(
            "rbac.membership.removed",
            actor=actor,
            organization=locked_org,
            target_type="membership",
            target_id=target_id,
            client_ip=client_ip,
            metadata={
                "member_user_id": member_user_id,
                "roles_removed": sorted(str(r.pk) for r in roles),
            },
        )


# ----------------------------------------------------------------------- role assignment
def replace_membership_roles(
    *,
    actor: Any,
    organization: Organization,
    membership_id: Any,
    role_ids: Iterable[Any],
    client_ip: str | None = None,
) -> list[Role]:
    """Make ``role_ids`` the exact role set of a membership."""
    requested = set(role_ids)
    with transaction.atomic():
        locked_org = _lock_organization(organization)
        acting, locked = _lock_actor_and_targets(locked_org, actor, [membership_id])
        target = _target(locked, membership_id)
        roles = {r.pk: r for r in _roles(locked_org, requested)}
        if set(roles) != requested:
            raise exceptions.ValidationError({"role_ids": ["Unknown role."]})
        current_ids = _role_ids(locked_org, target)
        current = {r.pk: r for r in _roles(locked_org, current_ids)}
        added = [roles[i] for i in sorted(requested - current_ids, key=str)]
        removed = [current[i] for i in sorted(current_ids - requested, key=str)]
        if not added and not removed:
            return sorted(roles.values(), key=lambda r: r.name)
        owner_added = any(r.is_owner for r in added)
        owner_removed = any(r.is_owner for r in removed)
        relinquishing = target.pk == acting.membership.pk
        if relinquishing:
            # The only self-change: an Owner giving up the Owner role and nothing else.
            if added or len(removed) != 1 or not owner_removed or not acting.is_owner:
                raise SelfModificationError()
        else:
            acting.require("members.manage")
            if (owner_added or owner_removed or SystemRole.OWNER in _keys(current)) and (
                not acting.is_owner
            ):
                raise OwnerRoleRestrictedError()
            permissions, _ = _authority([*added, *removed])
            if not permissions <= acting.permissions:
                raise DelegationError()
        if owner_removed:
            _ensure_owner_remains(locked_org, _active_owner_ids(locked_org) - {target.pk})
        MembershipRole.objects.for_organization(locked_org).filter(
            membership=target, role__in=removed
        ).delete()
        for role in added:
            MembershipRole(
                organization=locked_org, membership=target, role=role, assigned_by=actor
            ).save(force_insert=True)
        _record_role_changes(
            actor=actor,
            organization=locked_org,
            target=target,
            added=added,
            removed=removed,
            relinquishing=relinquishing,
            client_ip=client_ip,
        )
    return sorted(roles.values(), key=lambda r: r.name)


def _keys(roles: dict[Any, Role]) -> set[str | None]:
    return {r.system_key for r in roles.values()}


def _record_role_changes(
    *,
    actor: Any,
    organization: Organization,
    target: Membership,
    added: list[Role],
    removed: list[Role],
    relinquishing: bool,
    client_ip: str | None,
) -> None:
    audit.record(
        "rbac.membership.roles_replaced",
        actor=actor,
        organization=organization,
        target_type="membership",
        target_id=target.pk,
        client_ip=client_ip,
        metadata={
            "member_user_id": target.user_id,
            "roles_added": [str(r.pk) for r in added],
            "roles_removed": [str(r.pk) for r in removed],
        },
    )
    if any(r.is_owner for r in added):
        _record_owner_event("rbac.owner.granted", actor, organization, target, client_ip)
    if any(r.is_owner for r in removed):
        action = "rbac.owner.relinquished" if relinquishing else "rbac.owner.revoked"
        _record_owner_event(action, actor, organization, target, client_ip)


def _record_owner_event(
    action: str, actor: Any, organization: Organization, target: Membership, ip: str | None
) -> None:
    audit.record(
        action,
        actor=actor,
        organization=organization,
        target_type="membership",
        target_id=target.pk,
        client_ip=ip,
        metadata={"member_user_id": target.user_id},
    )


# ---------------------------------------------------------------------------------- roles
def _lock_role(organization: Organization, role_id: Any) -> Role:
    role: Role | None = (
        Role.objects.for_organization(organization).select_for_update().filter(pk=role_id).first()
    )
    if role is None:
        raise exceptions.NotFound()
    return role


def _active_role_codes(role: Role) -> set[str]:
    return {
        code
        for code in role.permissions.filter(is_deprecated=False).values_list("code", flat=True)
        if registry.is_active(code)
    }


def _save_role(role: Role, **kwargs: Any) -> None:
    try:
        with transaction.atomic():
            role.full_clean(validate_unique=False, validate_constraints=False)
            role.save(**kwargs)
    except IntegrityError as exc:
        diag = getattr(exc.__cause__, "diag", None)
        if getattr(diag, "constraint_name", None) == ROLE_NAME_UNIQUE:
            raise RoleNameTakenError() from exc
        raise


def create_role(
    *,
    actor: Any,
    organization: Organization,
    name: str,
    description: str = "",
    permissions: Iterable[str] = (),
    client_ip: str | None = None,
) -> Role:
    codes = _validated_codes(permissions)
    with transaction.atomic():
        locked_org = _lock_organization(organization)
        acting, _ = _lock_actor_and_targets(locked_org, actor)
        acting.require("roles.manage")
        if not codes <= acting.permissions:
            raise DelegationError()
        role = Role(organization=locked_org, name=name.strip(), description=description.strip())
        _save_role(role, force_insert=True)
        role.permissions.set(Permission.objects.filter(code__in=codes))
        audit.record(
            "rbac.role.created",
            actor=actor,
            organization=locked_org,
            target_type="role",
            target_id=role.pk,
            changes={"name": (None, role.name)},
            client_ip=client_ip,
            metadata={"permissions_added": sorted(codes)},
        )
    return role


def update_role(
    *,
    actor: Any,
    organization: Organization,
    role_id: Any,
    changes: dict[str, Any],
    client_ip: str | None = None,
) -> Role:
    unexpected = set(changes) - ROLE_EDITABLE_FIELDS
    if unexpected:
        msg = f"Fields not editable: {', '.join(sorted(unexpected))}"
        raise ValueError(msg)
    requested_codes = _validated_codes(changes["permissions"]) if "permissions" in changes else None
    with transaction.atomic():
        locked_org = _lock_organization(organization)
        acting, _ = _lock_actor_and_targets(locked_org, actor)
        acting.require("roles.manage")
        role = _lock_role(locked_org, role_id)
        fields = {
            f: str(changes[f]).strip()
            for f in ("name", "description")
            if f in changes and str(changes[f]).strip() != getattr(role, f)
        }
        current = _active_role_codes(role)
        added = sorted(requested_codes - current) if requested_codes is not None else []
        removed = sorted(current - requested_codes) if requested_codes is not None else []
        if not fields and not added and not removed:
            return role
        if role.is_owner or (role.is_system and fields):
            raise SystemRoleProtectedError()
        if not set(added) | set(removed) <= acting.permissions:
            raise DelegationError()
        if fields:
            before = {f: getattr(role, f) for f in fields}
            for field, value in fields.items():
                setattr(role, field, value)
            _save_role(role, update_fields=[*fields, "updated_at"])
            audit.record(
                "rbac.role.updated",
                actor=actor,
                organization=locked_org,
                target_type="role",
                target_id=role.pk,
                changes={f: (before[f], fields[f]) for f in fields},
                client_ip=client_ip,
            )
        if added or removed:
            role.permissions.add(*Permission.objects.filter(code__in=added))
            role.permissions.remove(*Permission.objects.filter(code__in=removed))
            audit.record(
                "rbac.role.permissions_changed",
                actor=actor,
                organization=locked_org,
                target_type="role",
                target_id=role.pk,
                client_ip=client_ip,
                metadata={"permissions_added": added, "permissions_removed": removed},
            )
    return role


def delete_role(
    *, actor: Any, organization: Organization, role_id: Any, client_ip: str | None = None
) -> None:
    with transaction.atomic():
        locked_org = _lock_organization(organization)
        acting, _ = _lock_actor_and_targets(locked_org, actor)
        acting.require("roles.manage")
        role = _lock_role(locked_org, role_id)
        if role.is_system:
            raise SystemRoleProtectedError()
        if MembershipRole.objects.for_organization(locked_org).filter(role=role).exists():
            raise RoleInUseError()
        codes = sorted(_active_role_codes(role))
        role_pk, name = role.pk, role.name
        role.permissions.clear()
        role.delete()
        audit.record(
            "rbac.role.deleted",
            actor=actor,
            organization=locked_org,
            target_type="role",
            target_id=role_pk,
            changes={"name": (name, None)},
            client_ip=client_ip,
            metadata={"permissions_removed": codes},
        )


# --------------------------------------------------------------- organization integration
def require_fresh_permission(organization: Organization, actor: Any, code: str) -> None:
    """For services outside this app: call after locking ``organization`` in the transaction."""
    acting, _ = _lock_actor_and_targets(organization, actor)
    acting.require(code)


# ------------------------------------------------------------------ global deactivation
def assert_deactivation_keeps_owners(user: User) -> None:
    """Refuse to deactivate the last active Owner of any active organization.

    Call inside the deactivation transaction, **after** locking the user row. Locks every
    organization in which the user has a membership (ascending id), then re-counts active Owners
    other than this user in each organization where the user is an active Owner. Raises
    :class:`LastOwnerError` listing every blocking organization; the caller's transaction rolls
    back, so nothing changes in any organization.
    """
    blocking = _blocking_organizations(user, lock=True)
    if blocking:
        raise LastOwnerError(blocking)


def _blocking_organizations(user: User, *, lock: bool) -> list[Any]:
    organization_ids = sorted(
        set(Membership.objects.filter(user_id=user.pk).values_list("organization_id", flat=True))
    )
    queryset = Organization.objects.filter(pk__in=organization_ids).order_by("pk")
    organizations = list(queryset.select_for_update() if lock else queryset)
    blocking = []
    for organization in organizations:
        if organization.status != OrganizationStatus.ACTIVE:
            continue
        owners = _active_owner_memberships_by_user(organization)
        if user.pk in owners and not owners.keys() - {user.pk}:
            blocking.append(organization.pk)
    return blocking


def _active_owner_memberships_by_user(organization: Organization) -> dict[Any, Any]:
    return dict(
        MembershipRole.objects.for_organization(organization)
        .filter(
            role__system_key=SystemRole.OWNER,
            membership__status=MembershipStatus.ACTIVE,
            membership__user__is_active=True,
        )
        .values_list("membership__user_id", "membership_id")
    )


def deactivation_blockers(user: User) -> tuple[str, ...]:
    """Lock-free preview for forms (the staff admin). The locked check remains authoritative.

    It takes no locks, so calling it never breaks the lock order of a later deactivation.
    """
    return tuple(sorted(str(pk) for pk in _blocking_organizations(user, lock=False)))
