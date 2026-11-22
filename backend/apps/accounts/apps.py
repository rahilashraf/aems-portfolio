from django.apps import AppConfig


class AccountsConfig(AppConfig):
    """Identity: custom user model, JWT authentication with server-side sessions, password flows
    and authentication abuse protection (Batch 3; ADR-0004, ADR-0008, ADR-0013)."""

    name = "apps.accounts"
    label = "accounts"
    verbose_name = "Accounts"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        from . import schema  # noqa: F401, PLC0415 - registers the OpenAPI auth extension
