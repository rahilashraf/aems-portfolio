"""RBAC domain errors (RFC 9457 Problem Details with stable codes; ADR-0007, ADR-0017)."""

from collections.abc import Iterable
from typing import Any

from rest_framework import status

from apps.core.api.exceptions import ConflictError, DomainError


class RbacForbiddenError(DomainError):
    """The actor may not perform this change (403). Raised from inside the locked transaction."""

    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "You do not have permission to perform this action."
    default_code = "permission_denied"


class DelegationError(RbacForbiddenError):
    default_detail = "You can only grant or remove permissions and roles that you hold yourself."
    default_code = "delegation_not_allowed"


class OwnerRoleRestrictedError(RbacForbiddenError):
    default_detail = "Only an Owner can grant or remove the Owner role or change an Owner."
    default_code = "owner_role_restricted"


class SelfModificationError(RbacForbiddenError):
    default_detail = (
        "You cannot change your own membership or roles. An Owner may only give up the Owner "
        "role while another active Owner remains."
    )
    default_code = "self_modification_not_allowed"


class LastOwnerError(ConflictError):
    """The change would leave an active organization without an active Owner (409).

    ``organization_ids`` lists every blocking organization for internal callers (for example the
    staff admin). It is never part of the API response, which could otherwise disclose other
    tenants.
    """

    default_detail = "This change would leave the organization without an active Owner."
    default_code = "last_owner"

    def __init__(self, organization_ids: Iterable[Any] = (), **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.organization_ids = tuple(sorted(str(i) for i in organization_ids))


class SystemRoleProtectedError(ConflictError):
    default_detail = (
        "System roles cannot be renamed or deleted, and the Owner role cannot be changed."
    )
    default_code = "system_role_protected"


class RoleNameTakenError(ConflictError):
    default_detail = "A role with this name already exists in the organization."
    default_code = "role_name_taken"


class RoleInUseError(ConflictError):
    default_detail = "This role is assigned to members. Remove it from them first."
    default_code = "role_in_use"


class UnknownPermissionError(DomainError):
    default_detail = "Unknown or deprecated permission code."
    default_code = "unknown_permission"
