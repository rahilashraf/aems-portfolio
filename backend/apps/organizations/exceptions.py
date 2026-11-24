from rest_framework import exceptions, status

from apps.core.api.exceptions import ConflictError, DomainError


class OrganizationSlugTakenError(ConflictError):
    default_detail = "An organization with this slug already exists."
    default_code = "organization_slug_taken"


class OrganizationStatusTransitionError(ConflictError):
    default_detail = (
        "This status change is not allowed. Organizations become active only when an Owner "
        "accepts the initial invitation, and can only be suspended while active."
    )
    default_code = "organization_status_transition_not_allowed"


# ------------------------------------------------------------------------------ invitations
class InvitationNotFoundError(DomainError):
    """Unknown, expired, revoked or already used: one answer for all (no enumeration)."""

    status_code = status.HTTP_404_NOT_FOUND
    default_detail = "This invitation is not valid. It may have expired or been used or revoked."
    default_code = "invitation_invalid"


class SignInRequiredError(DomainError, exceptions.NotAuthenticated):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "Sign in with the invited email address to accept this invitation."
    default_code = "sign_in_required"


class InvitationEmailMismatchError(DomainError):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "This invitation was sent to a different email address."
    default_code = "invitation_email_mismatch"


class AlreadyMemberError(ConflictError):
    default_detail = "This person is already a member of the organization."
    default_code = "already_member"


class InvitationAlreadyPendingError(ConflictError):
    default_detail = (
        "A pending invitation already exists for this email address. Revoke it before sending "
        "another one."
    )
    default_code = "invitation_already_pending"


class InvitationNotPendingError(ConflictError):
    default_detail = "Only a pending invitation can be revoked."
    default_code = "invitation_not_pending"


class InvitationAuthorityRevokedError(ConflictError):
    default_detail = (
        "This invitation can no longer be accepted because the roles it grants are no longer "
        "within the inviter's authority. Ask the organization for a new invitation."
    )
    default_code = "invitation_authority_revoked"


class OrganizationUnavailableError(ConflictError):
    default_detail = "This organization is not accepting members right now."
    default_code = "organization_unavailable"


class OrganizationNotProvisioningError(ConflictError):
    default_detail = "Initial Owner invitations exist only for provisioning organizations."
    default_code = "organization_not_provisioning"


class AccountInactiveError(DomainError):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "This account is deactivated."
    default_code = "account_inactive"
