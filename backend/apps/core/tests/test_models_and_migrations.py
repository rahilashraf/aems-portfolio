"""Abstract base models and migration state."""

import datetime as dt
import time
import uuid

import pytest
from django.apps import apps
from django.db import connection, models

from apps.core.models import BaseModel, CreatedAtModel, TimeStampedModel, UUIDModel
from tests.fixtures_app.models import Widget


class TestAbstractModels:
    @pytest.mark.parametrize("model", [UUIDModel, CreatedAtModel, TimeStampedModel, BaseModel])
    def test_models_are_abstract(self, model: type[models.Model]) -> None:
        assert model._meta.abstract

    def test_uuid_primary_key_definition(self) -> None:
        field = UUIDModel._meta.get_field("id")
        assert isinstance(field, models.UUIDField)
        assert field.primary_key
        assert not field.editable
        assert field.default is uuid.uuid4

    def test_timestamp_definitions(self) -> None:
        created = TimeStampedModel._meta.get_field("created_at")
        updated = TimeStampedModel._meta.get_field("updated_at")
        assert isinstance(created, models.DateTimeField)
        assert created.auto_now_add
        assert created.db_index  # type: ignore[attr-defined]  # missing from django-stubs
        assert isinstance(updated, models.DateTimeField)
        assert updated.auto_now

    def test_base_model_combines_all_fields(self) -> None:
        names = {f.name for f in BaseModel._meta.get_fields()}
        assert names == {"id", "created_at", "updated_at"}


@pytest.mark.django_db
class TestConcreteBehaviour:
    def test_primary_key_is_random_uuid4(self) -> None:
        first = Widget.objects.create(name="a", category="c")
        second = Widget.objects.create(name="b", category="c")

        assert isinstance(first.pk, uuid.UUID)
        assert first.pk.version == 4
        assert first.pk != second.pk

    def test_timestamps_are_timezone_aware_utc(self) -> None:
        widget = Widget.objects.create(name="a", category="c")
        widget.refresh_from_db()

        for value in (widget.created_at, widget.updated_at):
            assert value.tzinfo is not None
            assert value.utcoffset() == dt.timedelta(0)

    def test_updated_at_changes_on_save_created_at_does_not(self) -> None:
        widget = Widget.objects.create(name="a", category="c")
        created, updated = widget.created_at, widget.updated_at
        time.sleep(0.01)
        widget.name = "renamed"
        widget.save()
        widget.refresh_from_db()

        assert widget.created_at == created
        assert widget.updated_at > updated


@pytest.mark.django_db
class TestMigrationState:
    def test_no_default_auth_user_tables(self) -> None:
        tables = set(connection.introspection.table_names())
        assert not tables & {"auth_user", "auth_user_groups", "auth_user_user_permissions"}
        assert {"accounts_user", "auth_group", "auth_permission"} <= tables

    def test_custom_user_model_is_active(self) -> None:
        from django.conf import settings  # noqa: PLC0415
        from django.contrib.auth import get_user_model  # noqa: PLC0415

        assert settings.AUTH_USER_MODEL == "accounts.User"
        assert get_user_model()._meta.db_table == "accounts_user"
        for label in ("auth", "admin", "sessions", "contenttypes"):
            assert apps.is_installed(f"django.contrib.{label}")

    def test_core_has_no_concrete_models(self) -> None:
        assert list(apps.get_app_config("core").get_models()) == []


@pytest.mark.django_db
class TestVerifyNoDefaultTablesCommand:
    def test_passes_on_clean_schema(self) -> None:
        from io import StringIO  # noqa: PLC0415

        from django.core.management import call_command  # noqa: PLC0415

        out = StringIO()
        call_command("verify_no_default_tables", stdout=out)
        assert "OK" in out.getvalue()

    def test_fails_when_auth_table_exists(self) -> None:
        from django.core.management import call_command  # noqa: PLC0415
        from django.core.management.base import CommandError  # noqa: PLC0415

        with connection.cursor() as cursor:
            cursor.execute("CREATE TABLE auth_user (id integer)")
        with pytest.raises(CommandError, match="auth_user"):
            call_command("verify_no_default_tables")
