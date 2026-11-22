"""User model, manager, email normalization and case-insensitive uniqueness (ADR-0008)."""

import threading
from typing import Any

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import identify_hasher
from django.core.exceptions import ValidationError
from django.db import IntegrityError, connection, connections, transaction
from django.test import override_settings

from apps.accounts.exceptions import EmailAlreadyRegisteredError
from apps.accounts.models import EMAIL_UNIQUE_CONSTRAINT, User
from apps.accounts.normalization import normalize_email

from .conftest import PASSWORD

BASE_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]


class TestNormalization:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("  Alice@Example.ORG ", "alice@example.org"),
            ("\tBOB@example.org\n", "bob@example.org"),
            (
                "\uff41\uff4c\uff49\uff43\uff45@\uff45\uff58\uff41\uff4d\uff50\uff4c\uff45.org",
                "alice@example.org",
            ),  # fullwidth -> NFKC
            ("\u3000carol@example.org\u3000", "carol@example.org"),  # ideographic spaces
            ("\uff24ave@Example.org", "dave@example.org"),
        ],
    )
    def test_trim_nfkc_lowercase(self, raw: str, expected: str) -> None:
        assert normalize_email(raw) == expected

    def test_none_and_empty(self) -> None:
        assert normalize_email(None) == ""
        assert normalize_email("   ") == ""


@pytest.mark.django_db
class TestManager:
    def test_get_user_model(self) -> None:
        assert get_user_model() is User

    def test_create_user(self) -> None:
        user = User.objects.create_user("  New.User@Example.org ", PASSWORD, full_name="New User")

        assert user.email == "new.user@example.org"
        assert user.pk.version == 4
        assert user.is_active
        assert not user.is_staff
        assert not user.is_superuser
        assert user.check_password(PASSWORD)
        assert user.password != PASSWORD
        assert user.password_changed_at is not None
        assert user.date_joined is not None

    def test_create_user_without_password_is_unusable(self) -> None:
        user = User.objects.create_user("nopass@example.org", None, full_name="No Pass")
        assert not user.has_usable_password()

    def test_create_superuser(self) -> None:
        admin = User.objects.create_superuser("root@example.org", PASSWORD, full_name="Root")
        assert admin.is_staff
        assert admin.is_superuser

    @pytest.mark.parametrize("flags", [{"is_staff": False}, {"is_superuser": False}])
    def test_superuser_flags_are_enforced(self, flags: dict[str, bool]) -> None:
        with pytest.raises(ValueError, match="is_staff=True and is_superuser=True"):
            User.objects.create_superuser("bad@example.org", PASSWORD, full_name="Bad", **flags)

    @pytest.mark.parametrize("email", ["", "   ", "not-an-email", "a@", "@b.org"])
    def test_invalid_email_rejected(self, email: str) -> None:
        with pytest.raises((ValueError, ValidationError)):
            User.objects.create_user(email, PASSWORD, full_name="X")

    def test_natural_key_lookup_is_normalized(self) -> None:
        user = User.objects.create_user("case@example.org", PASSWORD, full_name="Case")
        assert User.objects.get_by_natural_key("  CASE@Example.Org ") == user

    def test_save_and_clean_normalize(self) -> None:
        user = User(email="  Mixed@Example.ORG", full_name="Mixed")
        user.set_password(PASSWORD)
        user.full_clean()
        user.save()
        assert user.email == "mixed@example.org"
        assert str(user) == "mixed@example.org"

    def test_clean_requires_email(self) -> None:
        with pytest.raises(ValidationError):
            User(email="   ", full_name="X", password="x").clean()

    def test_password_hash_is_argon2id(self) -> None:
        with override_settings(PASSWORD_HASHERS=BASE_HASHERS):
            user = User.objects.create_user("argon@example.org", PASSWORD, full_name="Argon")
            assert identify_hasher(user.password).algorithm == "argon2"
            assert user.password.startswith("argon2$argon2id$")
            assert user.check_password(PASSWORD)


@pytest.mark.django_db
class TestCaseInsensitiveUniqueness:
    def test_case_variant_is_rejected_by_manager(self) -> None:
        User.objects.create_user("dup@example.org", PASSWORD, full_name="A")
        with pytest.raises(EmailAlreadyRegisteredError):
            User.objects.create_user("DUP@Example.org", PASSWORD, full_name="B")

    def test_uniqueness_error_leaves_outer_transaction_usable(self) -> None:
        User.objects.create_user("keep@example.org", PASSWORD, full_name="A")
        with transaction.atomic():
            with pytest.raises(EmailAlreadyRegisteredError):
                User.objects.create_user("KEEP@example.org", PASSWORD, full_name="B")
            # The savepoint rolled back only the failed insert; the transaction still works.
            assert User.objects.filter(email="keep@example.org").count() == 1

    def test_database_constraint_holds_even_if_normalization_is_bypassed(self) -> None:
        User.objects.create_user("raw@example.org", PASSWORD, full_name="A")
        other = User.objects.create_user("other@example.org", PASSWORD, full_name="B")
        with pytest.raises(IntegrityError) as excinfo, transaction.atomic():
            # QuerySet.update() skips save(): only the functional index can stop this.
            User.objects.filter(pk=other.pk).update(email="RAW@EXAMPLE.ORG")
        assert EMAIL_UNIQUE_CONSTRAINT in str(excinfo.value)

    def test_unrelated_integrity_errors_are_not_masked(self) -> None:
        with pytest.raises(IntegrityError):
            User.objects.create_user("nulls@example.org", PASSWORD, full_name=None)

    def test_constraint_is_a_functional_lower_index(self) -> None:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT indexdef FROM pg_indexes WHERE indexname = %s", [EMAIL_UNIQUE_CONSTRAINT]
            )
            (indexdef,) = cursor.fetchone()
        assert "UNIQUE" in indexdef
        assert "lower((email)::text)" in indexdef


@pytest.mark.django_db(transaction=True)
def test_concurrent_registration_race_yields_exactly_one_account() -> None:
    """Pre-checks cannot prevent races; the constraint + savepoint handling must."""
    variants = ["race@example.org", "RACE@example.org", "Race@Example.org", " race@EXAMPLE.org "]
    barrier = threading.Barrier(len(variants))
    outcomes: list[Any] = []

    def worker(email: str) -> None:
        try:
            barrier.wait(timeout=10)
            User.objects.create_user(email, PASSWORD, full_name="Racer")
            outcomes.append("created")
        except EmailAlreadyRegisteredError:
            outcomes.append("conflict")
        except BaseException as exc:
            outcomes.append(exc)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=worker, args=(v,)) for v in variants]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert sorted(map(str, outcomes)) == ["conflict", "conflict", "conflict", "created"]
    assert User.objects.filter(email="race@example.org").count() == 1
