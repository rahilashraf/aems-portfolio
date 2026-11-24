from django.apps import AppConfig
from django.db.models.signals import post_migrate


class RbacConfig(AppConfig):
    """Organization-scoped customizable RBAC (Batch 6; ADR-0005, ADR-0017)."""

    name = "apps.rbac"
    label = "rbac"
    verbose_name = "Roles and permissions"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        from .catalog import register_role_permissions  # noqa: PLC0415
        from .registry import sync_permissions_after_migrate  # noqa: PLC0415

        register_role_permissions()
        post_migrate.connect(
            sync_permissions_after_migrate,
            sender=self,
            dispatch_uid="aems.rbac.sync_permissions",
        )
