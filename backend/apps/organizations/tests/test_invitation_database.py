"""Database safeguards for invitations: constraints, composite foreign keys, the terminal-state
trigger, role deletion, the admin and the upgrade from Batch 6 (ADR-0018)."""

import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from django.contrib import admin
from django.db import DatabaseError, IntegrityError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone

from apps.accounts.models import User
from apps.organizations import invitations
from apps.organizations.models import (
    Invitation,
    InvitationEmail,
    InvitationRole,
    InvitationStatus,
    Membership,
    Organization,
)
from apps.rbac.exceptions import RoleInUseError
from apps.rbac.models import Role
from apps.rbac.services import delete_role
from apps.rbac.tests.conftest import Team, custom_role, role

from .invitation_helpers import accept, deliver, new_account_body

pytestmark = pytest.mark.django_db
EMAIL = "x@example.org"


@pytest.fixture
def invitation(team: Team) -> Invitation:
    return invitations.create_invitation(
        actor=team.owner, organization=team.org, email=EMAIL, role_ids=[team.auditors.pk]
    )


def _raw(sql: str, params: list[Any]) -> None:
    with transaction.atomic(), connection.cursor() as cursor:
        cursor.execute(sql, params)
        cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")


class TestConstraints:
    def test_one_pending_invitation_per_address(self, invitation: Invitation, team: Team) -> None:
        duplicate = Invitation(
            organization=team.org,
            email=EMAIL,
            invited_by=team.owner,
            expires_at=timezone.now() + timedelta(days=1),
        )
        with pytest.raises(IntegrityError), transaction.atomic():
            duplicate.save()

    @pytest.mark.parametrize(
        "values",
        [
            {"email": "Upper@Example.org"},
            {"email": ""},
            {"status": "unknown"},
            {"status": "accepted"},  # no acceptance timestamp or user
            {"status": "revoked"},  # no revocation timestamp
            {"token_hash": "not-a-digest"},
            {"expires_at": "past"},
        ],
    )
    def test_check_constraints(self, team: Team, values: dict[str, Any]) -> None:
        fields: dict[str, Any] = {
            "organization": team.org,
            "email": "y@example.org",
            "invited_by": team.owner,
            "expires_at": timezone.now() + timedelta(days=1),
            **values,
        }
        if fields["expires_at"] == "past":
            fields["expires_at"] = timezone.now() - timedelta(days=1)
        with pytest.raises(IntegrityError), transaction.atomic():
            Invitation(**fields).save()

    def test_one_pending_initial_owner_invitation_per_organization(
        self, platform_admin: User
    ) -> None:
        from apps.organizations.services import create_organization  # noqa: PLC0415

        organization = create_organization(
            actor=platform_admin,
            name="P",
            slug="p-org",
            organization_type="other",
            initial_owner_email="a@example.org",
        )
        with pytest.raises(IntegrityError), transaction.atomic():
            Invitation(
                organization=organization,
                email="b@example.org",
                invited_by=platform_admin,
                is_initial_owner=True,
                expires_at=timezone.now() + timedelta(days=1),
            ).save()

    def test_cross_tenant_roles_are_rejected(self, invitation: Invitation, team: Team) -> None:
        foreign = role(team.other, "member")
        with pytest.raises(ValueError, match="own organization"):
            InvitationRole(organization=team.org, invitation=invitation, role=foreign).save()
        with pytest.raises(IntegrityError):
            _raw(
                "INSERT INTO organizations_invitationrole (id, organization_id, invitation_id, "
                "role_id, created_at, updated_at) VALUES (%s, %s, %s, %s, now(), now())",
                [uuid.uuid4(), team.org.pk, invitation.pk, foreign.pk],
            )
        with pytest.raises(IntegrityError), transaction.atomic():
            InvitationRole(organization=team.org, invitation=invitation, role=team.auditors).save()
        assert str(InvitationRole.objects.first()).startswith("InvitationRole")


class TestTrigger:
    def test_terminal_invitations_never_change(self, invitation: Invitation, team: Team) -> None:
        token = deliver()[EMAIL]
        assert accept(token, new_account_body()).status_code == 200
        for sql in (
            "UPDATE organizations_invitation SET status = 'revoked', revoked_at = now(), "
            "accepted_at = NULL, accepted_by_id = NULL WHERE id = %s",
            "UPDATE organizations_invitation SET status = 'pending', accepted_at = NULL, "
            "accepted_by_id = NULL WHERE id = %s",
            "UPDATE organizations_invitation SET token_hash = NULL WHERE id = %s",
            "DELETE FROM organizations_invitation WHERE id = %s",
        ):
            with pytest.raises(DatabaseError):
                _raw(sql, [invitation.pk])
        invitation.refresh_from_db()
        assert invitation.status == InvitationStatus.ACCEPTED
        assert str(invitation).startswith("Invitation")
        assert str(InvitationEmail.objects.get()).startswith("InvitationEmail")

    def test_identity_columns_are_immutable_even_while_pending(
        self, invitation: Invitation, team: Team
    ) -> None:
        for column, value in (
            ("email", "other@example.org"),
            ("organization_id", team.other.pk),
            ("is_initial_owner", True),
            ("invited_by_id", team.admin.pk),
            ("expires_at", timezone.now() + timedelta(days=30)),
        ):
            with pytest.raises(DatabaseError):
                _raw(
                    f"UPDATE organizations_invitation SET {column} = %s WHERE id = %s",  # noqa: S608
                    [value, invitation.pk],
                )
        with pytest.raises(DatabaseError):
            _raw("DELETE FROM organizations_invitation WHERE id = %s", [invitation.pk])


class TestRoleDeletion:
    def test_role_granted_by_a_pending_invitation_cannot_be_deleted(self, team: Team) -> None:
        spare = custom_role(team.org, "Spare", "members.view")
        pending = invitations.create_invitation(
            actor=team.owner, organization=team.org, email=EMAIL, role_ids=[spare.pk]
        )
        with pytest.raises(RoleInUseError):
            delete_role(actor=team.owner, organization=team.org, role_id=spare.pk)
        invitations.revoke_invitation(
            actor=team.owner, organization=team.org, invitation_id=pending.pk
        )
        delete_role(actor=team.owner, organization=team.org, role_id=spare.pk)
        assert not Role.objects.filter(pk=spare.pk).exists()
        assert Invitation.objects.get(pk=pending.pk).status == InvitationStatus.REVOKED


def test_admin_is_read_only_and_hides_the_digest(rf: Any, invitation: Invitation) -> None:
    model_admin = admin.site._registry[Invitation]
    request = rf.get("/")
    assert not model_admin.has_add_permission(request)
    assert not model_admin.has_change_permission(request, invitation)
    assert not model_admin.has_delete_permission(request, invitation)
    assert "token_hash" in (model_admin.exclude or ())


BATCH_6 = [
    ("organizations", "0002_membership_id_org_uniq"),
    ("rbac", "0003_seed_system_roles"),
    ("audit", "0002_append_only_trigger"),
    ("accounts", "0002_passwordresetoutbox"),
    ("fixtures_app", "0002_tenantnote"),
]
INVITATION_TABLES = {
    "organizations_invitation",
    "organizations_invitationrole",
    "organizations_invitationemail",
}


@pytest.mark.django_db(transaction=True)
def test_upgrade_from_batch_6_preserves_data_and_activates_nothing() -> None:
    executor = MigrationExecutor(connection)
    executor.migrate(BATCH_6)
    assert not INVITATION_TABLES & set(connection.introspection.table_names())
    old = executor.loader.project_state(BATCH_6).apps
    now = timezone.now()
    user = old.get_model("accounts", "User").objects.create(
        email="legacy@example.org", full_name="Legacy", password="!", password_changed_at=now
    )
    organization_model = old.get_model("organizations", "Organization")
    for slug, status in (("prov", "provisioning"), ("live", "active")):
        org = organization_model.objects.create(
            name=slug, slug=slug, organization_type="school", created_by=user, status=status
        )
        old.get_model("organizations", "Membership").objects.create(
            organization=org, user=user, status="active"
        )
    models = (User, Organization, Membership, Role)
    before = [list(m.objects.order_by("pk").values()) for m in models]

    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate(executor.loader.graph.leaf_nodes())

    assert set(connection.introspection.table_names()) >= INVITATION_TABLES
    assert [list(m.objects.order_by("pk").values()) for m in models] == before
    assert not Invitation.objects.exists()  # no invitation is created for existing organizations
    assert Organization.objects.get(slug="prov").status == "provisioning"


@pytest.mark.django_db(transaction=True)
def test_invitation_migrations_are_reversible() -> None:
    executor = MigrationExecutor(connection)
    executor.migrate([("organizations", "0002_membership_id_org_uniq")])
    assert not INVITATION_TABLES & set(connection.introspection.table_names())
    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate(executor.loader.graph.leaf_nodes())
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_trigger WHERE tgname = 'organizations_invitation_protect'")
        assert cursor.fetchone() == (1,)


def test_make_user_fixture_is_available(make_user: Callable[..., User]) -> None:
    assert make_user().pk is not None
