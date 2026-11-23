from apps.core.api.exceptions import ConflictError


class OrganizationSlugTakenError(ConflictError):
    default_detail = "An organization with this slug already exists."
    default_code = "organization_slug_taken"


class OrganizationStatusTransitionError(ConflictError):
    default_detail = (
        "This status change is not allowed. Organizations become active only when an Owner "
        "accepts the initial invitation, and can only be suspended while active."
    )
    default_code = "organization_status_transition_not_allowed"
