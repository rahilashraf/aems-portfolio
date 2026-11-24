from django.apps import AppConfig


class OrganizationsConfig(AppConfig):
    """Organizations, memberships and the tenant-scoping foundation (ADR-0003, ADR-0015)."""

    name = "apps.organizations"
    label = "organizations"
    verbose_name = "Organizations"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        from apps.rbac.catalog import register_organization_permissions  # noqa: PLC0415

        register_organization_permissions()
