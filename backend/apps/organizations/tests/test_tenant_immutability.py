"""Tenant immutability of TenantScopedModel rows across ORM write paths (AEMS-012, AEMS-013).

Application-level enforcement only: raw SQL, historical models in data migrations and
``loaddata`` (which saves with ``raw=True``) are outside it (see ``apps.organizations.tenancy``).
"""

from collections.abc import Callable
from typing import Any

import pytest
from django.db import DatabaseError, DataError, IntegrityError, connection, transaction
from django.test.utils import CaptureQueriesContext

from apps.organizations.models import Organization
from apps.organizations.tenancy import (
    UNKNOWN,
    MissingTenantContextError,
    TenantReassignmentError,
)
from tests.fixtures_app.models import TenantNote

pytestmark = pytest.mark.django_db

TENANT_FIELD_NAMES = ["organization", "organization_id"]


@pytest.fixture
def orgs(make_org: Callable[..., Organization]) -> tuple[Organization, Organization]:
    return make_org(), make_org()


@pytest.fixture
def note(orgs: tuple[Organization, Organization]) -> TenantNote:
    return TenantNote.objects.create(organization=orgs[0], title="original")


def _stored(note: TenantNote) -> tuple[Any, str]:
    row = TenantNote.objects.values_list("organization_id", "title").get(pk=note.pk)
    return row[0], row[1]


# ------------------------------------------------------------------ AEMS-012: bulk_create upserts
class TestBulkCreateUpsert:
    @pytest.mark.parametrize("field", TENANT_FIELD_NAMES)
    def test_conflict_update_cannot_reassign_the_organization(
        self, orgs: tuple[Organization, Organization], note: TenantNote, field: str
    ) -> None:
        org_a, org_b = orgs
        intruder = TenantNote(id=note.pk, organization=org_b, title="moved")
        with pytest.raises(TenantReassignmentError):
            TenantNote.objects.bulk_create(
                [intruder],
                update_conflicts=True,
                unique_fields=["id"],
                update_fields=[field, "title"],
            )
        assert _stored(note) == (org_a.pk, "original")

    def test_conflict_update_of_other_fields_still_works(
        self, orgs: tuple[Organization, Organization], note: TenantNote
    ) -> None:
        org_a, org_b = orgs
        # The organization on the incoming object is not written: only update_fields are.
        incoming = TenantNote(id=note.pk, organization=org_b, title="updated")
        TenantNote.objects.bulk_create(
            [incoming], update_conflicts=True, unique_fields=["id"], update_fields=["title"]
        )
        assert _stored(note) == (org_a.pk, "updated")

    def test_plain_bulk_create_still_works(self, orgs: tuple[Organization, Organization]) -> None:
        org_a, org_b = orgs
        created = TenantNote.objects.bulk_create(
            [TenantNote(organization=org_a, title="a"), TenantNote(organization=org_b, title="b")]
        )
        assert len(created) == 2
        assert TenantNote.objects.for_organization(org_b).get().title == "b"

    def test_ignore_conflicts_still_works(
        self, orgs: tuple[Organization, Organization], note: TenantNote
    ) -> None:
        org_a, org_b = orgs
        TenantNote.objects.bulk_create(
            [TenantNote(id=note.pk, organization=org_b, title="ignored")], ignore_conflicts=True
        )
        assert _stored(note) == (org_a.pk, "original")


class TestOtherWritePaths:
    @pytest.mark.parametrize("field", TENANT_FIELD_NAMES)
    def test_update_and_bulk_update(
        self, orgs: tuple[Organization, Organization], note: TenantNote, field: str
    ) -> None:
        org_a, org_b = orgs
        value = org_b if field == "organization" else org_b.pk
        with pytest.raises(TenantReassignmentError):
            TenantNote.objects.filter(pk=note.pk).update(**{field: value})
        loaded = TenantNote.objects.get(pk=note.pk)
        setattr(loaded, field, value)
        with pytest.raises(TenantReassignmentError):
            TenantNote.objects.bulk_update([loaded], [field])
        assert _stored(note) == (org_a.pk, "original")

    def test_update_or_create_cannot_reassign(
        self, orgs: tuple[Organization, Organization], note: TenantNote
    ) -> None:
        org_a, org_b = orgs
        with pytest.raises(TenantReassignmentError):
            TenantNote.objects.update_or_create(pk=note.pk, defaults={"organization": org_b})
        assert _stored(note) == (org_a.pk, "original")
        _obj, created = TenantNote.objects.update_or_create(
            pk=note.pk, defaults={"title": "via update_or_create"}
        )
        assert not created
        assert _stored(note) == (org_a.pk, "via update_or_create")

    def test_forced_update_of_an_unloaded_instance_cannot_reassign(
        self, orgs: tuple[Organization, Organization], note: TenantNote
    ) -> None:
        """An instance built in memory (never loaded) that targets an existing row."""
        org_a, org_b = orgs
        forged = TenantNote(
            id=note.pk, organization=org_b, title="forged", created_at=note.created_at
        )
        with CaptureQueriesContext(connection) as queries, pytest.raises(TenantReassignmentError):
            forged.save(force_update=True)
        assert len(queries.captured_queries) == 1  # reads the stored organization, writes nothing
        assert _stored(note) == (org_a.pk, "original")

    def test_update_fields_on_an_unloaded_instance_inserts_and_fails(
        self, orgs: tuple[Organization, Organization], note: TenantNote
    ) -> None:
        """Django inserts unsaved UUID-keyed instances even with update_fields: no reassignment."""
        org_a, org_b = orgs
        forged = TenantNote(
            id=note.pk, organization=org_b, title="forged", created_at=note.created_at
        )
        with pytest.raises(IntegrityError), transaction.atomic():
            forged.save(update_fields=["organization", "title"])
        assert _stored(note) == (org_a.pk, "original")

    def test_unloaded_instance_keeping_the_organization_can_update(
        self, orgs: tuple[Organization, Organization], note: TenantNote
    ) -> None:
        org_a, _ = orgs
        TenantNote(
            id=note.pk, organization=org_a, title="same tenant", created_at=note.created_at
        ).save(force_update=True)
        assert _stored(note) == (org_a.pk, "same tenant")

    def test_create_and_insert_paths_still_require_an_organization(self) -> None:
        with pytest.raises(MissingTenantContextError):
            TenantNote.objects.create(title="orphan")
        with pytest.raises(MissingTenantContextError):
            TenantNote(title="orphan").save(force_insert=True)

    def test_clearing_the_organization_is_rejected(
        self, orgs: tuple[Organization, Organization], note: TenantNote
    ) -> None:
        loaded = TenantNote.objects.get(pk=note.pk)
        loaded.organization_id = None  # type: ignore[assignment]
        with pytest.raises((MissingTenantContextError, TenantReassignmentError)):
            loaded.save()
        assert _stored(note)[0] == orgs[0].pk


# ------------------------------------------------------------- AEMS-013: deferred organization
def _deferred(note: TenantNote, how: str) -> TenantNote:
    queryset = TenantNote.objects.filter(pk=note.pk)
    loaded: TenantNote = (
        queryset.only("title").get() if how == "only" else queryset.defer("organization").get()
    )
    assert "organization_id" in loaded.get_deferred_fields()
    return loaded


@pytest.mark.parametrize("how", ["only", "defer"])
class TestDeferredOrganization:
    def test_unchanged_record_saves(self, note: TenantNote, how: str) -> None:
        loaded = _deferred(note, how)
        loaded.title = "renamed"
        loaded.save()
        assert _stored(note) == (note.organization_id, "renamed")

    def test_unchanged_record_saves_with_update_fields(self, note: TenantNote, how: str) -> None:
        loaded = _deferred(note, how)
        loaded.title = "partial"
        loaded.save(update_fields=["title"])
        assert _stored(note) == (note.organization_id, "partial")

    def test_saving_a_deferred_record_needs_no_extra_query(
        self, note: TenantNote, how: str
    ) -> None:
        loaded = _deferred(note, how)
        loaded.title = "one query"
        with CaptureQueriesContext(connection) as queries:
            loaded.save()
        assert len(queries.captured_queries) == 1  # the UPDATE itself
        assert (
            "organization_id"
            not in queries.captured_queries[0]["sql"].split("SET")[1].split("WHERE")[0]
        )

    @pytest.mark.parametrize("field", TENANT_FIELD_NAMES)
    def test_reassignment_is_rejected(
        self, orgs: tuple[Organization, Organization], note: TenantNote, how: str, field: str
    ) -> None:
        org_a, org_b = orgs
        loaded = _deferred(note, how)
        setattr(loaded, field, org_b if field == "organization" else org_b.pk)
        with pytest.raises(TenantReassignmentError):
            loaded.save()
        loaded = _deferred(note, how)
        setattr(loaded, field, org_b if field == "organization" else org_b.pk)
        with pytest.raises(TenantReassignmentError):
            loaded.save(update_fields=["organization", "title"])
        assert _stored(note) == (org_a.pk, "original")

    def test_lazily_loaded_organization_is_tracked(
        self, orgs: tuple[Organization, Organization], note: TenantNote, how: str
    ) -> None:
        org_a, org_b = orgs
        loaded = _deferred(note, how)
        assert loaded.organization_id == org_a.pk  # triggers the deferred load
        loaded.title = "after lazy load"
        loaded.save()
        assert _stored(note) == (org_a.pk, "after lazy load")
        loaded.organization = org_b
        with pytest.raises(TenantReassignmentError):
            loaded.save()
        assert _stored(note) == (org_a.pk, "after lazy load")

    def test_refresh_does_not_launder_a_reassignment(
        self, orgs: tuple[Organization, Organization], note: TenantNote, how: str
    ) -> None:
        org_a, org_b = orgs
        loaded = _deferred(note, how)
        loaded.organization = org_b
        loaded.refresh_from_db(fields=["title"])  # does not reload the organization
        with pytest.raises(TenantReassignmentError):
            loaded.save()
        loaded.refresh_from_db(fields=["organization"])  # really reloaded from the database
        loaded.save()
        assert _stored(note) == (org_a.pk, "original")


def test_fully_loaded_record_saves_with_and_without_update_fields(
    orgs: tuple[Organization, Organization], note: TenantNote
) -> None:
    loaded = TenantNote.objects.get(pk=note.pk)
    loaded.title = "ordinary"
    loaded.save()
    loaded.title = "partial"
    loaded.save(update_fields=["title"])
    assert _stored(note) == (orgs[0].pk, "partial")


def test_positional_bulk_create_upsert_is_also_rejected(
    orgs: tuple[Organization, Organization], note: TenantNote
) -> None:
    org_a, org_b = orgs
    intruder = TenantNote(id=note.pk, organization=org_b, title="moved")
    with pytest.raises(TenantReassignmentError):
        # objs, batch_size, ignore_conflicts, update_conflicts, update_fields, unique_fields
        TenantNote.objects.bulk_create([intruder], None, False, True, ["organization_id"], ["id"])
    assert _stored(note) == (org_a.pk, "original")


def test_unknown_baseline_is_explicit() -> None:
    assert repr(UNKNOWN) == "<unknown>"
    assert TenantNote()._loaded_organization_id is UNKNOWN


# ------------------------------------------------- AEMS-014: baseline after partial saves
def _set_clause(sql: str) -> str:
    return sql.split(" SET ", 1)[1].split(" WHERE ", 1)[0]


def _load(note: TenantNote, how: str) -> TenantNote:
    queryset = TenantNote.objects.filter(pk=note.pk)
    loaded: TenantNote = queryset.only("title").get() if how == "only" else queryset.get()
    return loaded


@pytest.mark.parametrize("how", ["full", "only"])
class TestBaselineAfterSaves:
    """The baseline is the last organization read from or inserted into the database."""

    def test_partial_save_does_not_launder_a_reassignment(
        self, orgs: tuple[Organization, Organization], note: TenantNote, how: str
    ) -> None:
        org_a, org_b = orgs
        loaded = _load(note, how)
        loaded.organization = org_b
        loaded.title = "partial"
        loaded.save(update_fields=["title"])  # does not write the organization: allowed
        assert _stored(note) == (org_a.pk, "partial")
        with pytest.raises(TenantReassignmentError):
            loaded.save()
        assert _stored(note) == (org_a.pk, "partial")

    def test_repeated_partial_saves(
        self, orgs: tuple[Organization, Organization], note: TenantNote, how: str
    ) -> None:
        org_a, org_b = orgs
        loaded = _load(note, how)
        loaded.organization = org_b
        for title in ("one", "two", "three"):
            loaded.title = title
            loaded.save(update_fields=["title"])
        with pytest.raises(TenantReassignmentError):
            loaded.save(update_fields=["organization", "title"])
        with pytest.raises(TenantReassignmentError):
            loaded.save()
        assert _stored(note) == (org_a.pk, "three")

    def test_empty_update_fields(
        self, orgs: tuple[Organization, Organization], note: TenantNote, how: str
    ) -> None:
        org_a, org_b = orgs
        loaded = _load(note, how)
        loaded.organization = org_b
        with CaptureQueriesContext(connection) as queries:
            loaded.save(update_fields=[])
        assert queries.captured_queries == []
        with pytest.raises(TenantReassignmentError):
            loaded.save()
        assert _stored(note) == (org_a.pk, "original")

    def test_rolled_back_save(
        self, orgs: tuple[Organization, Organization], note: TenantNote, how: str
    ) -> None:
        org_a, org_b = orgs
        loaded = _load(note, how)
        loaded.organization = org_b
        loaded.title = "rolled back"

        def save_then_fail() -> None:
            with transaction.atomic():
                loaded.save(update_fields=["title"])
                raise RuntimeError

        with pytest.raises(RuntimeError):
            save_then_fail()
        with pytest.raises(TenantReassignmentError):
            loaded.save()
        assert _stored(note) == (org_a.pk, "original")

    def test_failed_save(
        self, orgs: tuple[Organization, Organization], note: TenantNote, how: str
    ) -> None:
        org_a, org_b = orgs
        loaded = _load(note, how)
        loaded.organization = org_b
        loaded.title = "x" * 101  # exceeds the column length: the UPDATE fails
        with pytest.raises(DataError), transaction.atomic():
            loaded.save(update_fields=["title"])
        loaded.title = "valid"
        with pytest.raises(TenantReassignmentError):
            loaded.save()
        assert _stored(note) == (org_a.pk, "original")

    def test_refresh_only_resets_when_the_organization_is_reloaded(
        self, orgs: tuple[Organization, Organization], note: TenantNote, how: str
    ) -> None:
        org_a, org_b = orgs
        loaded = _load(note, how)
        loaded.organization = org_b
        loaded.save(update_fields=["title"])
        loaded.refresh_from_db(fields=["title"])
        with pytest.raises(TenantReassignmentError):
            loaded.save()
        loaded.refresh_from_db()  # reloads every non-deferred field, including the organization
        assert loaded.organization_id == org_a.pk
        loaded.title = "after reload"
        loaded.save()
        assert _stored(note) == (org_a.pk, "after reload")

    def test_explicit_tenant_field_updates(
        self, orgs: tuple[Organization, Organization], note: TenantNote, how: str
    ) -> None:
        org_a, org_b = orgs
        loaded = _load(note, how)
        loaded.organization = org_a  # unchanged value, explicitly assigned
        with CaptureQueriesContext(connection) as queries:
            loaded.save(update_fields=["organization"])
            loaded.save(update_fields=["organization_id"])
        # Nothing is left to write, so no UPDATE runs. A deferred-then-assigned organization has
        # no known baseline: each save reads the stored value once to verify it.
        sql = [q["sql"] for q in queries.captured_queries]
        assert not [s for s in sql if s.startswith("UPDATE")]
        assert len(sql) == (2 if how == "only" else 0)
        for field in TENANT_FIELD_NAMES:
            setattr(loaded, field, org_b if field == "organization" else org_b.pk)
            with pytest.raises(TenantReassignmentError):
                loaded.save(update_fields=[field])
        assert _stored(note) == (org_a.pk, "original")

    def test_updates_never_write_the_organization_column(
        self, orgs: tuple[Organization, Organization], note: TenantNote, how: str
    ) -> None:
        loaded = _load(note, how)
        loaded.title = "column check"
        with CaptureQueriesContext(connection) as queries:
            loaded.save()
            loaded.save(update_fields=["organization", "title"])
        updates = [q["sql"] for q in queries.captured_queries if q["sql"].startswith("UPDATE")]
        assert len(updates) == 2
        assert all('"organization_id"' not in _set_clause(sql) for sql in updates)

    def test_stale_instance_cannot_revert_a_concurrent_change(
        self,
        make_org: Callable[..., Organization],
        orgs: tuple[Organization, Organization],
        note: TenantNote,
        how: str,
    ) -> None:
        """An out-of-band change (outside ORM enforcement) is not undone by a stale save."""
        org_c = make_org()
        loaded = _load(note, how)
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE fixtures_app_tenantnote SET organization_id = %s WHERE id = %s",
                [org_c.pk, note.pk],
            )
        loaded.title = "stale save"
        loaded.save()
        assert _stored(note) == (org_c.pk, "stale save")


def test_baseline_is_set_by_insert_and_by_reload(orgs: tuple[Organization, Organization]) -> None:
    org_a, org_b = orgs
    created = TenantNote.objects.create(organization=org_a, title="new")
    assert created._loaded_organization_id == org_a.pk
    created.organization = org_b
    with pytest.raises(TenantReassignmentError):
        created.save()
    created.refresh_from_db(fields=["organization"])
    assert created._loaded_organization_id == org_a.pk
    created.save()


def test_saving_a_vanished_row_does_not_resurrect_it(
    orgs: tuple[Organization, Organization], note: TenantNote
) -> None:
    """Updates use explicit update_fields, so a deleted row is reported, never re-inserted."""
    loaded = TenantNote.objects.get(pk=note.pk)
    TenantNote.objects.filter(pk=note.pk).delete()
    with pytest.raises(DatabaseError), transaction.atomic():
        loaded.save()
    assert not TenantNote.objects.filter(pk=note.pk).exists()


def test_force_insert_of_a_loaded_instance_is_still_an_insert(note: TenantNote) -> None:
    loaded = TenantNote.objects.get(pk=note.pk)
    with pytest.raises(IntegrityError), transaction.atomic():
        loaded.save(force_insert=True)
