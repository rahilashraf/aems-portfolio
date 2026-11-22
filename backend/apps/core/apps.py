from django.apps import AppConfig


class CoreConfig(AppConfig):
    """Shared, domain-agnostic infrastructure: health checks, base models, request context,
    structured logging, Problem Details error handling, API conventions and documentation."""

    name = "apps.core"
    label = "core"
    verbose_name = "Core"

    def ready(self) -> None:
        from django.core.signals import request_finished  # noqa: PLC0415

        from . import checks  # noqa: F401, PLC0415 - registers system checks
        from .logging import configure_structlog  # noqa: PLC0415
        from .request_context import clear_request_context_on_request_finished  # noqa: PLC0415

        configure_structlog()
        request_finished.connect(
            clear_request_context_on_request_finished,
            dispatch_uid="apps.core.clear_request_context",
        )
