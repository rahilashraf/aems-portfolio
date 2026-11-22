from apps.core.api.exceptions import ConflictError


class EmailAlreadyRegisteredError(ConflictError):
    default_detail = "An account with this email address already exists."
    default_code = "email_already_registered"
