from django.apps import AppConfig
from django.db.models.signals import post_migrate


class AuditConfig(AppConfig):
    """Durable, append-only audit log (Batch 5; ADR-0006, ADR-0016)."""

    name = "apps.audit"
    label = "audit"
    verbose_name = "Audit"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        from apps.rbac.catalog import register_audit_permissions  # noqa: PLC0415

        from .privileges import grant_runtime_privileges_after_migrate  # noqa: PLC0415

        register_audit_permissions()
        post_migrate.connect(
            grant_runtime_privileges_after_migrate,
            sender=self,
            dispatch_uid="aems.audit.grant_runtime_privileges",
        )
