"""Organization/Membership models, validation, constraints and the tenant-scoping base."""

import pathlib
from collections.abc import Callable
from typing import Any

import pytest
from django.apps import apps
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import ValidationError
from django.db import IntegrityError, models, transaction

from apps.accounts.models import User
from apps.core import security_events
from apps.organizations import services
from apps.organizations.exceptions import OrganizationStatusTransitionError
from apps.organizations.models import (
    MEMBERSHIP_UNIQUE,
    ORGANIZATION_SLUG_UNIQUE,
    Membership,
    Organization,
    OrganizationStatus,
)
from apps.organizations.selectors import memberships_for_user, resolve_active_membership
from apps.organizations.services import update_organization_profile
from apps.organizations.tenancy import (
    MissingTenantContextError,
    TenantReassignmentError,
    TenantScopedModel,
)
from apps.organizations.validators import (
    normalize_slug,
    supported_timezones,
    validate_slug,
    validate_timezone,
)
from tests.fixtures_app.models import TenantNote

from .conftest import add_member

pytestmark = pytest.mark.django_db


class TestValidators:
    @pytest.mark.parametrize("raw", ["  Alpha-School ", "ALPHA-SCHOOL"])
    def test_slug_normalization(self, raw: str) -> None:
        assert normalize_slug(raw) == "alpha-school"

    @pytest.mark.parametrize("slug", ["abc", "a1-b2-c3", "x" * 63, "2026-cohort"])
    def test_valid_slugs(self, slug: str) -> None:
        validate_slug(slug)

    @pytest.mark.parametrize(
        "slug", ["ab", "x" * 64, "-abc", "abc-", "a--b", "a_b", "a b", "Abc", "é-school", ""]
    )
    def test_invalid_slugs(self, slug: str) -> None:
        with pytest.raises(ValidationError):
            validate_slug(slug)

    @pytest.mark.parametrize("tz", ["UTC", "Europe/London", "America/New_York", "Asia/Kolkata"])
    def test_valid_timezones(self, tz: str) -> None:
        validate_timezone(tz)

    @pytest.mark.parametrize("tz", ["", "Mars/Base", "europe/london", "localtime", "+05:00"])
    def test_invalid_timezones(self, tz: str) -> None:
        with pytest.raises(ValidationError):
            validate_timezone(tz)

    def test_timezone_database_is_available(self) -> None:
        assert len(supported_timezones()) > 300


class TestOrganizationConstraints:
    def test_defaults_to_provisioning(self, make_org: Callable[..., Organization]) -> None:
        organization = make_org(OrganizationStatus.PROVISIONING)
        assert organization.status == OrganizationStatus.PROVISIONING
        assert not organization.is_active
        assert organization.pk.version == 4
        assert str(organization) == organization.slug

    def test_slug_is_unique(self, make_org: Callable[..., Organization]) -> None:
        make_org(slug="taken")
        with pytest.raises(IntegrityError) as excinfo, transaction.atomic():
            make_org(slug="taken")
        assert ORGANIZATION_SLUG_UNIQUE in str(excinfo.value)

    @pytest.mark.parametrize(
        ("field", "value", "constraint"),
        [
            ("slug", "Bad Slug", "organizations_org_slug_format"),
            ("name", "", "organizations_org_name_not_blank"),
            ("status", "deleted", "organizations_org_status_valid"),
            ("organization_type", "company", "organizations_org_type_valid"),
        ],
    )
    def test_database_check_constraints(
        self, make_org: Callable[..., Organization], field: str, value: str, constraint: str
    ) -> None:
        organization = make_org()
        with pytest.raises(IntegrityError) as excinfo, transaction.atomic():
            Organization.objects.filter(pk=organization.pk).update(**{field: value})
        assert constraint in str(excinfo.value)

    def test_clean_normalizes(self, platform_admin: User) -> None:
        organization = Organization(
            name="  Spaced  ",
            slug=" Mixed-Case ",
            organization_type="school",
            created_by=platform_admin,
        )
        organization.full_clean()
        assert (organization.name, organization.slug) == ("Spaced", "mixed-case")

    def test_creator_cannot_be_deleted(
        self, make_org: Callable[..., Organization], platform_admin: User
    ) -> None:
        make_org()
        with pytest.raises(models.ProtectedError):
            platform_admin.delete()


class TestMembership:
    def test_user_can_belong_to_several_organizations(
        self, make_org: Callable[..., Organization], make_user: Callable[..., User]
    ) -> None:
        user = make_user()
        add_member(make_org(), user)
        add_member(make_org(), user)
        assert Membership.objects.filter(user=user).count() == 2

    def test_duplicate_membership_is_rejected(
        self, make_org: Callable[..., Organization], make_user: Callable[..., User]
    ) -> None:
        organization, user = make_org(), make_user()
        add_member(organization, user)
        with pytest.raises(IntegrityError) as excinfo, transaction.atomic():
            add_member(organization, user)
        assert MEMBERSHIP_UNIQUE in str(excinfo.value)

    def test_invalid_status_is_rejected_by_the_database(
        self, make_org: Callable[..., Organization], make_user: Callable[..., User]
    ) -> None:
        membership = add_member(make_org(), make_user())
        with pytest.raises(IntegrityError), transaction.atomic():
            Membership.objects.filter(pk=membership.pk).update(status="owner")

    def test_member_user_cannot_be_hard_deleted(
        self, make_org: Callable[..., Organization], make_user: Callable[..., User]
    ) -> None:
        user = make_user()
        add_member(make_org(), user)
        with pytest.raises(models.ProtectedError):
            user.delete()


class TestTenantScopedModel:
    def test_every_tenant_model_has_a_non_null_protected_organization(self) -> None:
        tenant_models = [
            m
            for m in apps.get_models()
            if issubclass(m, TenantScopedModel) and not m._meta.abstract
        ]
        assert Membership in tenant_models
        assert TenantNote in tenant_models
        for model in tenant_models:
            field = model._meta.get_field("organization")
            assert isinstance(field, models.ForeignKey)
            assert field.related_model is Organization
            assert not field.null
            assert not field.editable
            assert getattr(field, "db_index", False)
            assert field.remote_field.on_delete is models.PROTECT
            assert hasattr(model.objects, "for_organization")

    def test_for_organization_scopes_and_fails_closed(
        self, make_org: Callable[..., Organization]
    ) -> None:
        org_a, org_b = make_org(), make_org()
        note_a = TenantNote.objects.create(organization=org_a, title="a")
        TenantNote.objects.create(organization=org_b, title="b")
        assert list(TenantNote.objects.for_organization(org_a)) == [note_a]
        with pytest.raises(MissingTenantContextError):
            TenantNote.objects.for_organization(None)
        with pytest.raises(MissingTenantContextError):
            TenantNote.objects.for_organization(Organization())  # unsaved

    def test_create_without_organization_fails_closed(self) -> None:
        with pytest.raises(MissingTenantContextError):
            TenantNote(title="orphan").save()

    def test_organization_cannot_be_reassigned(self, make_org: Callable[..., Organization]) -> None:
        org_a, org_b = make_org(), make_org()
        note = TenantNote.objects.create(organization=org_a, title="a")
        loaded = TenantNote.objects.get(pk=note.pk)
        loaded.organization = org_b
        with pytest.raises(TenantReassignmentError):
            loaded.save()
        note.organization = org_b  # instance created in this process
        with pytest.raises(TenantReassignmentError):
            note.save()
        with pytest.raises(TenantReassignmentError):
            TenantNote.objects.filter(pk=note.pk).update(organization=org_b)
        with pytest.raises(TenantReassignmentError):
            TenantNote.objects.filter(pk=note.pk).update(organization_id=org_b.pk)
        with pytest.raises(TenantReassignmentError):
            TenantNote.objects.bulk_update([loaded], ["organization"])
        assert TenantNote.objects.get(pk=note.pk).organization_id == org_a.pk

    def test_other_fields_still_update(self, make_org: Callable[..., Organization]) -> None:
        note = TenantNote.objects.create(organization=make_org(), title="a")
        loaded = TenantNote.objects.get(pk=note.pk)
        loaded.title = "b"
        loaded.save()
        TenantNote.objects.filter(pk=note.pk).update(title="c")
        TenantNote.objects.bulk_update([loaded], ["title"])
        assert TenantNote.objects.get(pk=note.pk).title == "b"

    def test_organization_cannot_be_deleted_while_it_owns_rows(
        self, make_org: Callable[..., Organization], make_user: Callable[..., User]
    ) -> None:
        organization = make_org()
        add_member(organization, make_user())
        with pytest.raises(models.ProtectedError):
            organization.delete()

    def test_activation_helper_is_test_only(self) -> None:
        """No application module references the test-only activation helper."""
        app_root = pathlib.Path(__file__).resolve().parents[2]
        offenders = [
            str(path)
            for path in app_root.rglob("*.py")
            if "tests" not in path.parts and "activate_for_tests" in path.read_text()
        ]
        assert offenders == []


def test_status_constants() -> None:
    assert set(OrganizationStatus.values) == {"provisioning", "active", "suspended"}
    assert Organization._meta.get_field("status").default == OrganizationStatus.PROVISIONING


class TestSelectorsAndServices:
    def test_resolution_rejects_anonymous_inactive_and_malformed(
        self, make_org: Callable[..., Organization], make_user: Callable[..., User]
    ) -> None:
        organization, user = make_org(), make_user()
        membership = add_member(organization, user)
        assert resolve_active_membership(user, organization.pk) == membership
        assert resolve_active_membership(user, str(organization.pk)) == membership
        assert resolve_active_membership(AnonymousUser(), organization.pk) is None
        for bad in (None, "nope", 12, "00000000-0000-0000"):
            assert resolve_active_membership(user, bad) is None
        user.is_active = False
        assert resolve_active_membership(user, organization.pk) is None
        assert list(memberships_for_user(user)) == []
        assert str(membership) == f"Membership {membership.pk}"

    def test_profile_update_service_for_batch_6(
        self,
        make_org: Callable[..., Organization],
        platform_admin: User,
        django_capture_on_commit_callbacks: Any,
    ) -> None:
        captured: list[Any] = []
        unregister = security_events.register_sink(captured.append)
        try:
            organization = make_org()
            with django_capture_on_commit_callbacks(execute=True):
                updated = update_organization_profile(
                    actor=platform_admin,
                    organization=organization,
                    changes={"name": "Renamed", "timezone": "Europe/Paris"},
                )
            assert (updated.name, updated.timezone) == ("Renamed", "Europe/Paris")
            [event] = [e for e in captured if e.name == "organization.profile_updated"]
            assert event.metadata["changed_fields"] == ["name", "timezone"]
            with pytest.raises(ValueError, match="status"):
                update_organization_profile(
                    actor=platform_admin, organization=organization, changes={"status": "active"}
                )
            with pytest.raises(ValidationError):
                update_organization_profile(
                    actor=platform_admin, organization=organization, changes={"timezone": "Nowhere"}
                )
            pending = make_org(OrganizationStatus.PROVISIONING)
            with pytest.raises(OrganizationStatusTransitionError):
                update_organization_profile(
                    actor=platform_admin, organization=pending, changes={"name": "x"}
                )
        finally:
            unregister()

    def test_unrelated_integrity_errors_propagate(
        self, platform_admin: User, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*_args: Any, **_kwargs: Any) -> None:
            raise IntegrityError("other constraint")

        monkeypatch.setattr(Organization, "save", boom)
        with pytest.raises(IntegrityError):
            services.create_organization(
                actor=platform_admin, name="X", slug="xyz", organization_type="school"
            )
