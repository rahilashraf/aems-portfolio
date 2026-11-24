from apps.organizations.permissions import IsPlatformAdministrator

_AUDIT_VIEW = "audit.view_auditlog"


class IsPlatformAuditor(IsPlatformAdministrator):
    """Active staff with the explicit ``audit.view_auditlog`` permission (read-only)."""

    method_permissions = {"GET": _AUDIT_VIEW, "HEAD": _AUDIT_VIEW, "OPTIONS": _AUDIT_VIEW}
