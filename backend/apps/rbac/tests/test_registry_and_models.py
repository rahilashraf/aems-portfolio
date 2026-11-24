"""Permission registry and sync, models, database safeguards and system-role seeding."""

import uuid
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from django.db import DatabaseError, IntegrityError, connection, transaction

from apps.accounts.models import User
from apps.organizations.models import Organization, OrganizationStatus, OrganizationType
from apps.organizations.services import create_organization
from apps.rbac import catalog, engine
from apps.rbac.models import CrossTenantAssignmentError, MembershipRole, Permission, Role
from apps.rbac.registry import (
    PermissionRegistrationError,
    PermissionRegistry,
    registry,
    sync_permissions,
)
from apps.rbac.services import SYSTEM_ROLE_DEFINITIONS, seed_system_roles

from .conftest import Team, member, role

PHASE_1_CATALOG = {
    "organization.view",
    "organization.update",
    "members.view",
    "members.manage",
    "invitations.manage",
    "roles.view",
    "roles.manage",
    "audit.view",
}


@pytest.fixture
def extra_permission() -> Iterator[str]:
    """Temporarily register a new permission (as a future app would)."""
    code = "reports.export"
    registry.register(code, "Export reports.", category="reports")
    try:
        yield code
    finally:
        registry._definitions.pop(code)


# ------------------------------------------------------------------------------- registry
class TestRegistry:
    def test_phase_1_catalog_is_registered_by_the_owning_apps(self) -> None:
        assert registry.active_codes() == PHASE_1_CATALOG
        assert {d.category for d in registry.definitions()} == {
            "organization",
            "members",
            "invitations",
            "roles",
            "audit",
        }

    def test_identical_registration_is_idempotent_and_conflicts_are_rejected(self) -> None:
        local = PermissionRegistry()
        first = local.register("things.view", "View things.", category="things")
        assert local.register("things.view", "View things.", category="things") == first
        with pytest.raises(PermissionRegistrationError, match="different definition"):
            local.register("things.view", "Something else.", category="things")
        with pytest.raises(PermissionRegistrationError, match="different definition"):
            local.register("things.view", "View things.", category="things", deprecated=True)

    @pytest.mark.parametrize(
        ("code", "description", "category"),
        [
            ("Things.view", "x", "things"),
            ("things", "x", "things"),
            ("things.view.all", "x", "things"),
            ("things.view", "", "things"),
            ("things.view", "x" * 256, "things"),
            ("things.view", "x", "Things"),
        ],
    )
    def test_invalid_definitions_are_rejected(
        self, code: str, description: str, category: str
    ) -> None:
        with pytest.raises(PermissionRegistrationError):
            PermissionRegistry().register(code, description, category=category)

    def test_unknown_and_deprecated_codes_are_inactive(self) -> None:
        local = PermissionRegistry()
        local.register("things.view", "View things.", category="things")
        local.register("things.old", "Old.", category="things", deprecated=True)
        assert local.is_active("things.view")
        assert not local.is_active("things.old")
        assert not local.is_active("things.unknown")
        assert local.unknown_or_inactive(["things.view", "things.old", "x.y"]) == [
            "things.old",
            "x.y",
        ]
        assert local.get("things.view") is not None


@pytest.mark.django_db
class TestSync:
    def test_sync_is_idempotent(self) -> None:
        before = list(Permission.objects.values_list("code", "description", "is_deprecated"))
        assert sync_permissions() == {"created": 0, "updated": 0, "deprecated": 0}
        assert sync_permissions() == {"created": 0, "updated": 0, "deprecated": 0}
        assert list(Permission.objects.values_list("code", "description", "is_deprecated")) == (
            before
        )
        assert set(Permission.objects.values_list("code", flat=True)) == PHASE_1_CATALOG

    def test_new_and_updated_definitions_are_synced(self, extra_permission: str) -> None:
        Permission.objects.filter(code="audit.view").update(description="Stale.")
        assert sync_permissions() == {"created": 1, "updated": 1, "deprecated": 0}
        assert Permission.objects.get(code="audit.view").description.startswith("View")
        assert Permission.objects.filter(code=extra_permission, is_deprecated=False).exists()

    def test_unregistered_codes_are_deprecated_not_deleted(self, team: Team) -> None:
        legacy = Permission.objects.create(code="legacy.view", description="Old.", category="x")
        team.auditors.permissions.add(legacy)
        assert sync_permissions()["deprecated"] == 1
        legacy.refresh_from_db()
        assert legacy.is_deprecated
        # The role keeps the historical link, but it grants nothing.
        assert team.auditors.permissions.filter(code="legacy.view").exists()
        assert "legacy.view" not in engine.fresh_permissions(team.membership(team.auditor).pk)[0]

    def test_sync_preserves_role_assignments(self, team: Team) -> None:
        links = list(MembershipRole.objects.values_list("membership_id", "role_id"))
        permissions = list(Role.permissions.through.objects.values_list("role_id", "permission_id"))
        sync_permissions()
        assert list(MembershipRole.objects.values_list("membership_id", "role_id")) == links
        assert (
            list(Role.permissions.through.objects.values_list("role_id", "permission_id"))
            == permissions
        )

    def test_owner_gains_new_permissions_automatically_others_do_not(
        self, team: Team, extra_permission: str
    ) -> None:
        sync_permissions()
        owner_permissions, is_owner = engine.fresh_permissions(team.membership(team.owner).pk)
        admin_permissions, _ = engine.fresh_permissions(team.membership(team.admin).pk)
        assert is_owner
        assert extra_permission in owner_permissions
        assert extra_permission not in admin_permissions
        assert not role(team.org, "admin").permissions.filter(code=extra_permission).exists()


# --------------------------------------------------------------------- database safeguards
def _insert_raw_assignment(organization_id: Any, membership_id: Any, role_id: Any) -> None:
    with transaction.atomic(), connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO rbac_membershiprole "
            "(id, organization_id, membership_id, role_id, assigned_at, created_at, "
            "updated_at) VALUES (%s, %s, %s, %s, now(), now(), now())",
            [uuid.uuid4(), organization_id, membership_id, role_id],
        )
        cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")


def _bulk_create_immediately(assignment: MembershipRole) -> None:
    with transaction.atomic():
        MembershipRole.objects.bulk_create([assignment])
        with connection.cursor() as cursor:
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")


@pytest.mark.django_db
class TestDatabaseSafeguards:
    def test_permission_codes_are_immutable_and_rows_undeletable(self) -> None:
        for statement in (
            "UPDATE rbac_permission SET code = 'audit.read' WHERE code = 'audit.view'",
            "DELETE FROM rbac_permission WHERE code = 'audit.view'",
        ):
            with (
                pytest.raises(DatabaseError),
                transaction.atomic(),
                connection.cursor() as cursor,
            ):
                cursor.execute(statement)
        with pytest.raises(DatabaseError), transaction.atomic():
            Permission.objects.filter(code="audit.view").delete()
        assert Permission.objects.filter(code="audit.view").exists()
        # Other columns stay editable (sync updates descriptions and deprecation).
        Permission.objects.filter(code="audit.view").update(category="audit")

    def test_role_names_are_unique_per_organization_ignoring_case(self, team: Team) -> None:
        with pytest.raises(IntegrityError), transaction.atomic():
            Role(organization=team.org, name="auditors").save()
        Role(organization=team.other, name="AUDITORS").save()  # another organization: fine

    def test_one_system_role_per_key_and_valid_keys(self, team: Team) -> None:
        with pytest.raises(IntegrityError), transaction.atomic():
            Role(organization=team.org, name="Owner 2", is_system=True, system_key="owner").save()
        for values in (
            {"is_system": True, "system_key": "superowner"},
            {"is_system": True, "system_key": None},
            {"is_system": False, "system_key": "admin"},
            {"name": ""},
        ):
            fields = {"name": f"x-{uuid.uuid4()}", **values}
            with pytest.raises(IntegrityError), transaction.atomic():
                Role(organization=team.other, **fields).save()

    def test_cross_tenant_assignment_is_rejected_by_the_model(self, team: Team) -> None:
        membership = team.membership(team.norole)
        foreign_role = role(team.other, "admin")
        for organization in (team.org, team.other):
            with pytest.raises(CrossTenantAssignmentError):
                MembershipRole(
                    organization=organization, membership=membership, role=foreign_role
                ).save()
        assert not MembershipRole.objects.filter(membership=membership).exists()

    def test_cross_tenant_assignment_is_rejected_by_the_database(self, team: Team) -> None:
        membership = team.membership(team.norole)
        for organization, role_obj in (
            (team.org, role(team.other, "admin")),  # role of B on a membership of A
            (team.other, role(team.other, "admin")),  # organization column lies
        ):
            with pytest.raises(IntegrityError):
                _insert_raw_assignment(organization.pk, membership.pk, role_obj.pk)
        # bulk_create bypasses save(): the composite foreign key still refuses it.
        foreign = MembershipRole(
            organization=team.org, membership=membership, role=role(team.other, "admin")
        )
        with pytest.raises(IntegrityError):
            _bulk_create_immediately(foreign)

    def test_assigned_role_cannot_be_deleted_through_the_orm(self, team: Team) -> None:
        from django.db.models import ProtectedError  # noqa: PLC0415

        with pytest.raises(ProtectedError):
            role(team.org, "admin").delete()
        assert str(team.auditors) == "Auditors"
        assert str(Permission.objects.get(code="audit.view")) == "audit.view"
        assert str(MembershipRole.objects.first()).startswith("MembershipRole")


# ------------------------------------------------------------------------------- seeding
@pytest.mark.django_db
class TestSeeding:
    def test_new_organizations_get_system_roles_but_no_owner(self, platform_admin: User) -> None:
        organization = create_organization(
            actor=platform_admin,
            name="New",
            slug="new-org",
            organization_type=OrganizationType.OTHER,
            initial_owner_email="first-owner@example.org",
        )
        roles = {r.system_key: r for r in Role.objects.for_organization(organization)}
        assert set(roles) == {"owner", "admin", "member"}
        assert all(r.is_system for r in roles.values())
        assert not roles["owner"].permissions.exists()  # Owner is evaluated dynamically
        assert set(roles["admin"].permissions.values_list("code", flat=True)) == (
            catalog.ADMIN_DEFAULT_PERMISSIONS
        )
        assert set(roles["member"].permissions.values_list("code", flat=True)) == (
            catalog.MEMBER_DEFAULT_PERMISSIONS
        )
        organization.refresh_from_db()
        assert organization.status == OrganizationStatus.PROVISIONING
        assert not MembershipRole.objects.filter(organization=organization).exists()

    def test_seeding_is_idempotent_and_keeps_edits(self, team: Team) -> None:
        admin = role(team.org, "admin")
        admin.permissions.remove(Permission.objects.get(code="audit.view"))
        before = list(Role.objects.for_organization(team.org).values_list("pk", flat=True))
        roles = seed_system_roles(team.org)
        assert [r.system_key for r in roles] == [key for key, *_ in SYSTEM_ROLE_DEFINITIONS]
        assert list(Role.objects.for_organization(team.org).values_list("pk", flat=True)) == before
        assert not admin.permissions.filter(code="audit.view").exists()

    def test_seeding_failure_rolls_back_organization_creation(
        self, platform_admin: User, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def broken(_organization: Organization) -> None:
            raise DatabaseError("seeding failed")

        monkeypatch.setattr("apps.organizations.services.rbac.seed_system_roles", broken)
        with pytest.raises(DatabaseError):
            create_organization(
                actor=platform_admin,
                name="X",
                slug="x-org",
                organization_type="other",
                initial_owner_email="o@example.org",
            )
        assert not Organization.objects.filter(slug="x-org").exists()

    def test_platform_api_creation_seeds_roles(
        self, platform_admin: User, as_user: Callable[..., Any]
    ) -> None:
        response = as_user(platform_admin).post(
            "/api/v1/platform/organizations/",
            {
                "name": "Api",
                "slug": "api-org",
                "organization_type": "school",
                "initial_owner_email": "o@example.org",
            },
        )
        assert response.status_code == 201
        assert Role.objects.filter(organization_id=response.json()["id"]).count() == 3

    def test_member_helper_and_role_properties(self, team: Team) -> None:
        assert role(team.org, "owner").is_owner
        assert not team.auditors.is_owner
        assert member is not None
