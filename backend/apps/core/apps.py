from django.apps import AppConfig


class CoreConfig(AppConfig):
    """Shared, domain-agnostic infrastructure (health checks now; base models, error handling,
    tenancy helpers in later batches)."""

    name = "apps.core"
    label = "core"
    verbose_name = "Core"
