"""Seed the Phase 1 permission catalog and every organization's system roles (ADR-0017).

Existing organizations (created before Batch 6) receive the Owner, Admin and Member role
**definitions** with the default permissions. No membership is given a role here:

- seeding the Owner role is not assigning an Owner, and no organization changes status;
- existing memberships keep no roles, so they gain no permission they did not have before
  (fail closed). Owners are assigned through the API by an Owner, or by the Batch 7 initial
  Owner invitation.

The catalog is frozen here (historical migrations must not import live code). The ``post_migrate``
registry sync then upserts the live catalog idempotently.
"""

from typing import Any

from django.db import migrations

CATALOG = (
    ("organization.view", "View the organization profile.", "organization"),
    ("organization.update", "Edit the organization profile (name, timezone).", "organization"),
    ("members.view", "List members and view their roles.", "members"),
    ("members.manage", "Suspend, reactivate or remove members and assign roles.", "members"),
    ("invitations.manage", "Invite people to the organization (Batch 7).", "invitations"),
    ("roles.view", "List roles and the permission catalog.", "roles"),
    ("roles.manage", "Create, edit and delete roles.", "roles"),
    ("audit.view", "View the organization's audit history.", "audit"),
)
SYSTEM_ROLES = (
    ("owner", "Owner", "Full control of the organization, including ownership.", None),
    (
        "admin",
        "Admin",
        "Manages the organization, its members and roles; cannot manage ownership.",
        {code for code, _, _ in CATALOG},
    ),
    ("member", "Member", "Default role for members.", {"organization.view"}),
)


def seed(apps: Any, schema_editor: Any) -> None:
    Permission = apps.get_model("rbac", "Permission")
    Role = apps.get_model("rbac", "Role")
    Organization = apps.get_model("organizations", "Organization")
    for code, description, category in CATALOG:
        Permission.objects.get_or_create(
            code=code, defaults={"description": description, "category": category}
        )
    permissions = {p.code: p for p in Permission.objects.filter(is_deprecated=False)}
    for organization in Organization.objects.order_by("pk"):
        for key, name, description, defaults in SYSTEM_ROLES:
            role, created = Role.objects.get_or_create(
                organization=organization,
                system_key=key,
                defaults={"name": name, "description": description, "is_system": True},
            )
            if created and defaults:
                role.permissions.set([permissions[c] for c in sorted(defaults) if c in permissions])


class Migration(migrations.Migration):
    dependencies = [("rbac", "0002_database_safeguards")]

    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
