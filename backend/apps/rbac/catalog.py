"""Phase 1 permission catalog and system-role defaults (plan §6.1, ADR-0017).

Each owning application registers its codes from ``AppConfig.ready()`` by calling the matching
function below, so the catalog stays next to the code that checks it:

- ``organizations``: organization, members and invitations permissions;
- ``rbac``: role permissions;
- ``audit``: audit history.

``invitations.manage`` is registered for the Batch 7 invitation endpoints; no Batch 6 code path
grants anything because of it.
"""

from .registry import registry

ORGANIZATION_PERMISSIONS = (
    ("organization.view", "View the organization profile.", "organization"),
    ("organization.update", "Edit the organization profile (name, timezone).", "organization"),
    ("members.view", "List members and view their roles.", "members"),
    ("members.manage", "Suspend, reactivate or remove members and assign roles.", "members"),
    ("invitations.manage", "Invite people to the organization (Batch 7).", "invitations"),
)
ROLE_PERMISSIONS = (
    ("roles.view", "List roles and the permission catalog.", "roles"),
    ("roles.manage", "Create, edit and delete roles.", "roles"),
)
AUDIT_PERMISSIONS = (("audit.view", "View the organization's audit history.", "audit"),)

#: Permissions given to the editable system roles **when they are seeded**. Later catalog
#: additions are not granted to them automatically (only Owner gains them, dynamically).
ADMIN_DEFAULT_PERMISSIONS = frozenset(
    {
        "organization.view",
        "organization.update",
        "members.view",
        "members.manage",
        "invitations.manage",
        "roles.view",
        "roles.manage",
        "audit.view",
    }
)
MEMBER_DEFAULT_PERMISSIONS = frozenset({"organization.view"})


def _register(entries: tuple[tuple[str, str, str], ...]) -> None:
    for code, description, category in entries:
        registry.register(code, description, category=category)


def register_organization_permissions() -> None:
    _register(ORGANIZATION_PERMISSIONS)


def register_role_permissions() -> None:
    _register(ROLE_PERMISSIONS)


def register_audit_permissions() -> None:
    _register(AUDIT_PERMISSIONS)
