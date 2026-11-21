from django.apps import AppConfig


class FixturesAppConfig(AppConfig):
    """Test-only app: isolated models and views for exercising shared API infrastructure.

    Installed exclusively by ``config.settings.test``; never part of the deployed application.
    """

    name = "tests.fixtures_app"
    label = "fixtures_app"
    default_auto_field = "django.db.models.BigAutoField"
