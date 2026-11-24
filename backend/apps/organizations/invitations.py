"""Invitations and organization onboarding (Batch 7; plan §4.6, §5.3; ADR-0018).

Tokens
    256 random bits (``secrets.token_urlsafe(32)``), delivered by email only. The database keeps the
    SHA-256 digest of the token in the most recently sent email; the raw token is never stored,
    logged, audited or returned by an API. The delivery command (``invitation_outbox``) issues a
    fresh token for every send, so only the latest email's link is valid. Invitations expire after
    ``INVITATION_TTL_SECONDS`` (7 days), are single use and can be revoked.

Kinds
    - **Member invitations** to an active organization, issued through the tenant API by a member
      holding ``invitations.manage`` and every permission the invited roles confer (Owner role:
      Owners only), re-checked under the organization lock.
    - **The initial Owner invitation**, created with a provisioning organization (or issued again
      by a platform administrator). It grants only the Owner role, and accepting it is the **only**
      ``provisioning → active`` transition.

Acceptance (``accept_invitation``)
    - An account with the invited address exists: the caller must be signed in as that account
      (bearer token); no password is accepted.
    - No such account: the caller supplies a full name and a password (validated); the account is
      created with the invitation's address. Holding the emailed token proves the mailbox.

    Everything happens in one transaction: account, membership, roles, invitation consumption,
    activation and audit records commit together or not at all. Ownership of the invited address
    is re-checked against the locked user row (AEMS-018), so an address changed while the
    acceptance waited for the lock is rejected.

Lock order (ADR-0017, extended)
    user row → organization row → invitation row → new membership and role rows.
    An existing account is locked first (as global deactivation does); a new account is inserted
    first, which makes its row invisible to, and therefore unlockable by, anyone else until commit.
    Every invitation operation takes the organization lock, so invitations serialize with all
    RBAC mutations and deactivations of that organization.
"""

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from django.utils import timezone
from rest_framework import exceptions

from apps.accounts import ratelimit
from apps.accounts.exceptions import EmailAlreadyRegisteredError
from apps.accounts.models import User
from apps.accounts.normalization import normalize_email
from apps.audit import services as audit
from apps.rbac import services as rbac
from apps.rbac.models import MembershipRole, Role, SystemRole

from .exceptions import (
    AccountInactiveError,
    AlreadyMemberError,
    InvitationAlreadyPendingError,
    InvitationAuthorityRevokedError,
    InvitationEmailMismatchError,
    InvitationNotFoundError,
    InvitationNotPendingError,
    OrganizationNotProvisioningError,
    OrganizationUnavailableError,
    SignInRequiredError,
)
from .models import (
    INVITATION_PENDING_UNIQUE,
    Invitation,
    InvitationEmail,
    InvitationRole,
    InvitationStatus,
    Membership,
    MembershipStatus,
    Organization,
    OrganizationStatus,
)

TOKEN_BYTES = 32  # 256 bits
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")
MAX_INVITATION_ROLES = 20


def now() -> datetime:
    """The invitation clock (one place to read the time; tests move it instead of rows)."""
    return timezone.now()


# ---------------------------------------------------------------------------------- tokens
def new_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _find_by_token(token: str) -> Invitation | None:
    """The invitation whose current token is ``token``, or None. No row lock."""
    if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
        return None
    digest = hash_token(token)
    invitation: Invitation | None = (
        Invitation.objects.select_related("organization").filter(token_hash=digest).first()
    )
    if invitation is None or not hmac.compare_digest(invitation.token_hash or "", digest):
        return None
    return invitation


def _usable(invitation: Invitation, organization: Organization, now: datetime) -> bool:
    """Pending, unexpired, and the organization is in the state this kind of invitation needs."""
    if invitation.status != InvitationStatus.PENDING or invitation.expires_at <= now:
        return False
    if invitation.is_initial_owner:
        return organization.status == OrganizationStatus.PROVISIONING
    return organization.status == OrganizationStatus.ACTIVE


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local[:1]}{'*' * max(len(local) - 1, 1)}@{domain}"


# ----------------------------------------------------------------------------- validation
def _normalized_email(value: str) -> str:
    email = normalize_email(value)
    try:
        validate_email(email)
    except DjangoValidationError as exc:
        raise exceptions.ValidationError({"email": ["Enter a valid email address."]}) from exc
    return email


def _roles_of(organization: Organization, role_ids: list[Any]) -> list[Role]:
    requested = set(role_ids)
    if not requested or len(requested) > MAX_INVITATION_ROLES:
        raise exceptions.ValidationError(
            {"role_ids": [f"Choose between 1 and {MAX_INVITATION_ROLES} roles."]}
        )
    roles = list(Role.objects.for_organization(organization).filter(pk__in=requested))
    if {r.pk for r in roles} != requested:
        raise exceptions.ValidationError({"role_ids": ["Unknown role."]})
    return sorted(roles, key=lambda r: (r.name, str(r.pk)))


def _invitation_roles(invitation: Invitation) -> list[Role]:
    return list(
        Role.objects.for_organization(invitation.organization).filter(
            pk__in=InvitationRole.objects.for_organization(invitation.organization)
            .filter(invitation=invitation)
            .values("role_id")
        )
    )


def _expires_at(now: datetime) -> datetime:
    return now + timedelta(seconds=settings.INVITATION_TTL_SECONDS)


def _is_member(organization: Organization, email: str) -> bool:
    return Membership.objects.for_organization(organization).filter(user__email=email).exists()


def _expire_stale(organization: Organization, email: str, now: datetime, actor: Any) -> None:
    """Mark an expired pending invitation for this address as ``expired`` (organization locked)."""
    stale = (
        Invitation.objects.for_organization(organization)
        .select_for_update()
        .filter(email=email, status=InvitationStatus.PENDING, expires_at__lte=now)
    )
    for invitation in stale:
        invitation.status = InvitationStatus.EXPIRED
        invitation.save(update_fields=["status", "updated_at"])
        audit.record(
            "invitation.expired",
            actor=actor,
            organization=organization,
            target_type="invitation",
            target_id=invitation.pk,
            metadata={"initial_owner": invitation.is_initial_owner},
        )


def _create(
    *,
    organization: Organization,
    email: str,
    roles: list[Role],
    invited_by: Any,
    is_initial_owner: bool,
    now: datetime,
    client_ip: str | None,
) -> Invitation:
    invitation = Invitation(
        organization=organization,
        email=email,
        invited_by=invited_by,
        is_initial_owner=is_initial_owner,
        expires_at=_expires_at(now),
    )
    try:
        with transaction.atomic():
            invitation.save(force_insert=True)
    except IntegrityError as exc:
        diag = getattr(exc.__cause__, "diag", None)
        if getattr(diag, "constraint_name", None) == INVITATION_PENDING_UNIQUE:
            raise InvitationAlreadyPendingError() from exc
        raise
    for role in roles:
        InvitationRole(organization=organization, invitation=invitation, role=role).save(
            force_insert=True
        )
    InvitationEmail(invitation=invitation).save(force_insert=True)
    audit.record(
        "invitation.initial_owner_issued" if is_initial_owner else "invitation.created",
        actor=invited_by,
        organization=organization,
        target_type="invitation",
        target_id=invitation.pk,
        client_ip=client_ip,
        metadata={"roles_added": [str(r.pk) for r in roles], "initial_owner": is_initial_owner},
    )
    return invitation


# ------------------------------------------------------------------ member invitations
def create_invitation(
    *,
    actor: Any,
    organization: Organization,
    email: str,
    role_ids: list[Any],
    client_ip: str | None = None,
) -> Invitation:
    """Invite ``email`` to an active organization with some of its roles.

    Rejected, in this order and after locking the organization: inactive organization (409),
    missing ``invitations.manage`` (403), invalid roles (400), roles beyond the actor's authority
    or the Owner role for a non-Owner (403), an address that is already a member (409), and an
    address with an unexpired pending invitation (409; revoke it first). An expired pending
    invitation for the address is marked ``expired`` and replaced.
    """
    address = _normalized_email(email)
    with transaction.atomic():
        locked = Organization.objects.select_for_update(no_key=True).get(pk=organization.pk)
        if locked.status != OrganizationStatus.ACTIVE:
            raise OrganizationUnavailableError()
        acting = rbac.authorize_actor(locked, actor, "invitations.manage")
        roles = _roles_of(locked, role_ids)
        rbac.check_can_grant(acting, roles)
        if _is_member(locked, address):
            raise AlreadyMemberError()
        moment = now()
        _expire_stale(locked, address, moment, actor)
        return _create(
            organization=locked,
            email=address,
            roles=roles,
            invited_by=actor,
            is_initial_owner=False,
            now=moment,
            client_ip=client_ip,
        )


def revoke_invitation(
    *, actor: Any, organization: Organization, invitation_id: Any, client_ip: str | None = None
) -> Invitation:
    """Revoke a pending invitation. An accepted invitation cannot be revoked (its membership is
    managed through the member APIs), and the database trigger enforces it too."""
    with transaction.atomic():
        locked = Organization.objects.select_for_update(no_key=True).get(pk=organization.pk)
        acting = rbac.authorize_actor(locked, actor, "invitations.manage")
        invitation = (
            Invitation.objects.for_organization(locked)
            .select_for_update()
            .filter(pk=invitation_id)
            .first()
        )
        if invitation is None or invitation.is_initial_owner:
            raise exceptions.NotFound()
        rbac.check_can_grant(acting, _invitation_roles(invitation))
        return _revoke(invitation, locked, actor, client_ip)


def _revoke(
    invitation: Invitation, organization: Organization, actor: Any, client_ip: str | None
) -> Invitation:
    if invitation.status != InvitationStatus.PENDING:
        raise InvitationNotPendingError()
    invitation.status = InvitationStatus.REVOKED
    invitation.revoked_at = now()
    invitation.revoked_by = actor
    invitation.save(update_fields=["status", "revoked_at", "revoked_by", "updated_at"])
    audit.record(
        "invitation.revoked",
        actor=actor,
        organization=organization,
        target_type="invitation",
        target_id=invitation.pk,
        client_ip=client_ip,
        metadata={"initial_owner": invitation.is_initial_owner},
    )
    return invitation


# ----------------------------------------------------------------- initial Owner invitation
def issue_initial_owner_invitation(
    *, actor: Any, organization: Organization, email: str, client_ip: str | None = None
) -> Invitation:
    """Create the initial Owner invitation. Call inside the transaction that holds the
    organization row (organization creation, or :func:`reissue_initial_owner_invitation`)."""
    if organization.status != OrganizationStatus.PROVISIONING:
        raise OrganizationNotProvisioningError()
    owner_role = Role.objects.for_organization(organization).get(system_key=SystemRole.OWNER)
    moment = now()
    address = _normalized_email(email)
    _expire_stale(organization, address, moment, actor)
    return _create(
        organization=organization,
        email=address,
        roles=[owner_role],
        invited_by=actor,
        is_initial_owner=True,
        now=moment,
        client_ip=client_ip,
    )


def _require_platform_permission(actor: Any) -> None:
    """Re-check the platform administrator from the database inside the transaction."""
    actor_id = getattr(actor, "pk", None)
    fresh = (
        User.objects.filter(pk=actor_id, is_active=True, is_staff=True).first()
        if actor_id is not None
        else None
    )
    if fresh is None or not fresh.has_perm("organizations.manage_initial_owner_invitation"):
        raise exceptions.PermissionDenied()


def _pending_initial(organization: Organization) -> Invitation | None:
    return (
        Invitation.objects.for_organization(organization)
        .select_for_update()
        .filter(is_initial_owner=True, status=InvitationStatus.PENDING)
        .first()
    )


def reissue_initial_owner_invitation(
    *, actor: Any, organization: Organization, email: str, client_ip: str | None = None
) -> Invitation:
    """Platform administration: revoke the pending initial Owner invitation (if any) and issue a
    new one, for a provisioning organization only (also for organizations created before
    Batch 7, which have none)."""
    with transaction.atomic():
        locked = Organization.objects.select_for_update(no_key=True).get(pk=organization.pk)
        _require_platform_permission(actor)
        if locked.status != OrganizationStatus.PROVISIONING:
            raise OrganizationNotProvisioningError()
        current = _pending_initial(locked)
        if current is not None:
            _revoke(current, locked, actor, client_ip)
        return issue_initial_owner_invitation(
            actor=actor, organization=locked, email=email, client_ip=client_ip
        )


def revoke_initial_owner_invitation(
    *, actor: Any, organization: Organization, client_ip: str | None = None
) -> Invitation:
    with transaction.atomic():
        locked = Organization.objects.select_for_update(no_key=True).get(pk=organization.pk)
        _require_platform_permission(actor)
        if locked.status != OrganizationStatus.PROVISIONING:
            raise OrganizationNotProvisioningError()
        current = _pending_initial(locked)
        if current is None:
            raise exceptions.NotFound()
        return _revoke(current, locked, actor, client_ip)


def pending_initial_owner_invitation(organization: Organization) -> Invitation | None:
    return (
        Invitation.objects.for_organization(organization)
        .filter(is_initial_owner=True, status=InvitationStatus.PENDING)
        .select_related("email_delivery")
        .first()
    )


# ------------------------------------------------------------------- public: rate limit
def check_rate_limit(client_ip: str | None) -> None:
    from apps.accounts.services import (  # noqa: PLC0415 - avoid import cycle
        RateLimitedError,
        record_rate_limited,
    )

    result = ratelimit.check_all(
        [("invitation_ip", ratelimit.digest("ip", client_ip or "unknown"))]
    )
    if result is not None:
        record_rate_limited(result, scope="invitation", client_ip=client_ip)
        raise RateLimitedError(wait=result.retry_after)


# ---------------------------------------------------------------------- public: preview
@dataclass(frozen=True)
class InvitationPreview:
    organization_name: str
    email: str  # masked
    expires_at: datetime
    status: str
    next_step: str  # "accept" (signed in as the invitee) or "sign_in_or_create_account"


def preview_invitation(token: str, *, viewer: Any = None) -> InvitationPreview:
    """Minimal information for the token holder. Every unusable token gets the same 404."""
    invitation = _find_by_token(token)
    if invitation is None or not _usable(invitation, invitation.organization, now()):
        raise InvitationNotFoundError()
    signed_in_as_invitee = (
        getattr(viewer, "is_authenticated", False)
        and getattr(viewer, "is_active", False)
        and normalize_email(viewer.email) == invitation.email
    )
    return InvitationPreview(
        organization_name=invitation.organization.name,
        email=mask_email(invitation.email),
        expires_at=invitation.expires_at,
        status=InvitationStatus.PENDING,
        next_step="accept" if signed_in_as_invitee else "sign_in_or_create_account",
    )


# ------------------------------------------------------------------- public: acceptance
@dataclass(frozen=True)
class AcceptanceResult:
    organization: Organization
    membership: Membership
    roles: list[Role]
    account_created: bool


def accept_invitation(
    token: str,
    *,
    user: Any = None,
    full_name: str | None = None,
    password: str | None = None,
    client_ip: str | None = None,
) -> AcceptanceResult:
    """Accept an invitation (see the module documentation). Failures are recorded as independent
    security events after the transaction has rolled back."""
    try:
        return _accept(token, user=user, full_name=full_name, password=password, ip=client_ip)
    except (
        InvitationNotFoundError,
        SignInRequiredError,
        InvitationEmailMismatchError,
        AlreadyMemberError,
        InvitationAuthorityRevokedError,
        AccountInactiveError,
    ) as exc:
        audit.record_security_event(
            "invitation.accept_rejected",
            actor=user if isinstance(user, User) else None,
            client_ip=client_ip,
            metadata={"reason": exc.default_code},
        )
        raise


def _accept(
    token: str, *, user: Any, full_name: str | None, password: str | None, ip: str | None
) -> AcceptanceResult:
    invitation = _find_by_token(token)
    if invitation is None or not _usable(invitation, invitation.organization, now()):
        raise InvitationNotFoundError()
    authenticated = user if getattr(user, "is_authenticated", False) else None
    existing = User.objects.filter(email=invitation.email).first()
    if existing is not None:
        if authenticated is None:
            raise SignInRequiredError()
        if authenticated.pk != existing.pk:
            raise InvitationEmailMismatchError()
        if full_name is not None or password is not None:
            raise exceptions.ValidationError(
                {"password": ["Signed-in users accept without account details."]}
            )
        return _accept_locked(invitation.pk, token, user_id=existing.pk, new_account=None, ip=ip)
    if authenticated is not None:
        raise InvitationEmailMismatchError()
    full_name = (full_name or "").strip()
    errors: dict[str, list[str]] = {}
    if not full_name:
        errors["full_name"] = ["This field is required."]
    if not password:
        errors["password"] = ["This field is required."]
    if errors or password is None:
        raise exceptions.ValidationError(errors)
    try:
        password_validation.validate_password(
            password, User(email=invitation.email, full_name=full_name)
        )
    except DjangoValidationError as exc:
        raise exceptions.ValidationError({"password": list(exc.messages)}) from exc
    return _accept_locked(
        invitation.pk, token, user_id=None, new_account=(full_name, password), ip=ip
    )


def _accept_locked(
    invitation_id: Any,
    token: str,
    *,
    user_id: Any,
    new_account: tuple[str, str] | None,
    ip: str | None,
) -> AcceptanceResult:
    with transaction.atomic():
        # 1. The user row: lock an existing account (as deactivation does) or insert a new one.
        if new_account is None:
            account = User.objects.select_for_update(no_key=True).get(pk=user_id)
            if not account.is_active:
                raise AccountInactiveError()
        else:
            account = _create_account(invitation_id, *new_account)
        # 2. The organization row, 3. the invitation row.
        invitation = Invitation.objects.select_related("organization").get(pk=invitation_id)
        organization = Organization.objects.select_for_update(no_key=True).get(
            pk=invitation.organization_id
        )
        invitation = Invitation.objects.select_for_update().get(pk=invitation_id)
        moment = now()
        if not hmac.compare_digest(invitation.token_hash or "", hash_token(token)):
            raise InvitationNotFoundError()  # superseded by a newer email
        if invitation.status != InvitationStatus.PENDING or invitation.expires_at <= moment:
            raise InvitationNotFoundError()
        # AEMS-018: the account was matched to the invitation by address before any lock was
        # taken. The locked row is authoritative (SELECT … FOR UPDATE returns the latest
        # committed version, after any concurrent change to the row has committed), so the
        # address must still match now. An administrator may have changed it meanwhile.
        if normalize_email(account.email) != invitation.email:
            raise InvitationEmailMismatchError()
        if not _usable(invitation, organization, moment):
            raise OrganizationUnavailableError()
        roles = _invitation_roles(invitation)
        _revalidate(invitation, organization, roles)
        if Membership.objects.for_organization(organization).filter(user=account).exists():
            raise AlreadyMemberError()
        # 4. New rows: membership and role assignments.
        membership = Membership(
            organization=organization, user=account, status=MembershipStatus.ACTIVE
        )
        membership.save(force_insert=True)
        for role in roles:
            MembershipRole(
                organization=organization,
                membership=membership,
                role=role,
                assigned_by_id=invitation.invited_by_id,
            ).save(force_insert=True)
        invitation.status = InvitationStatus.ACCEPTED
        invitation.accepted_at = moment
        invitation.accepted_by = account
        invitation.save(update_fields=["status", "accepted_at", "accepted_by", "updated_at"])
        _record_acceptance(
            invitation=invitation,
            organization=organization,
            membership=membership,
            roles=roles,
            account=account,
            new_account=new_account,
            ip=ip,
        )
        if invitation.is_initial_owner:
            _activate(organization, account, ip)
    return AcceptanceResult(organization, membership, roles, new_account is not None)


def _create_account(invitation_id: Any, full_name: str, password: str) -> User:
    invitation = Invitation.objects.get(pk=invitation_id)
    try:
        with transaction.atomic():
            account = User.objects.create_user(invitation.email, password, full_name=full_name)
    except (IntegrityError, EmailAlreadyRegisteredError) as exc:
        # Someone registered this address concurrently (the unique index decided): that account
        # must sign in to accept. The token holder could learn this anyway by signing in.
        raise SignInRequiredError() from exc
    account.password_changed_at = now()
    account.save(update_fields=["password_changed_at"])
    return account


def _revalidate(invitation: Invitation, organization: Organization, roles: list[Role]) -> None:
    """Fail closed if the invitation would now grant more than its issuer may grant."""
    if invitation.is_initial_owner:
        if [r.system_key for r in roles] != [SystemRole.OWNER]:
            raise InvitationAuthorityRevokedError()
        return
    if not roles or not rbac.inviter_still_authorized(
        organization, invitation.invited_by_id, roles
    ):
        raise InvitationAuthorityRevokedError()


def _record_acceptance(
    *,
    invitation: Invitation,
    organization: Organization,
    membership: Membership,
    roles: list[Role],
    account: User,
    new_account: tuple[str, str] | None,
    ip: str | None,
) -> None:
    if new_account is not None:
        audit.record(
            "auth.account.created",
            actor=account,
            target_type="user",
            target_id=account.pk,
            client_ip=ip,
            metadata={"reason": "invitation"},
        )
    audit.record(
        "invitation.accepted",
        actor=account,
        organization=organization,
        target_type="invitation",
        target_id=invitation.pk,
        client_ip=ip,
        metadata={
            "initial_owner": invitation.is_initial_owner,
            "account_created": bool(new_account),
        },
    )
    audit.record(
        "rbac.membership.created",
        actor=account,
        organization=organization,
        target_type="membership",
        target_id=membership.pk,
        client_ip=ip,
        metadata={"member_user_id": account.pk, "invitation_id": invitation.pk},
    )
    audit.record(
        "rbac.membership.roles_assigned",
        actor=account,
        organization=organization,
        target_type="membership",
        target_id=membership.pk,
        client_ip=ip,
        metadata={"member_user_id": account.pk, "roles_added": [str(r.pk) for r in roles]},
    )
    if any(r.is_owner for r in roles):
        audit.record(
            "rbac.owner.granted",
            actor=account,
            organization=organization,
            target_type="membership",
            target_id=membership.pk,
            client_ip=ip,
            metadata={"member_user_id": account.pk, "invitation_id": invitation.pk},
        )


def _activate(organization: Organization, account: User, ip: str | None) -> None:
    """``provisioning → active``: only after an active Owner exists, in the same transaction."""
    if not rbac.active_owner_ids(organization):  # pragma: no cover - just created above
        raise OrganizationUnavailableError()
    previous = organization.status
    organization.status = OrganizationStatus.ACTIVE
    organization.save(update_fields=["status", "updated_at"])
    audit.record(
        "organization.activated",
        actor=account,
        organization=organization,
        target_type="organization",
        target_id=organization.pk,
        client_ip=ip,
        metadata={"previous_status": previous, "status": organization.status},
    )
