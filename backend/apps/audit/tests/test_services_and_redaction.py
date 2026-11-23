"""Audit service semantics: transactions, independence, logging and redaction."""

from typing import Any

import pytest
from django.db import DatabaseError, transaction
from django.test import Client

from apps.audit import services as audit
from apps.audit.models import AuditLog
from apps.audit.redaction import (
    METADATA_FIELDS,
    AuditDataError,
    clean_changes,
    clean_metadata,
    clean_target,
)
from apps.core import security_events
from apps.core.sanitization import is_sensitive_key
from apps.organizations.models import Organization
from apps.organizations.services import create_organization

from .conftest import rows

SECRET = "S3cret-Marker-Value-0123456789"  # appears in inputs; must never be stored


def _create(actor: Any, slug: str = "audited") -> Organization:
    return create_organization(actor=actor, name="Audited", slug=slug, organization_type="school")


# ------------------------------------------------------------------ transactional events
@pytest.mark.django_db
class TestTransactionalRecords:
    def test_mutation_creates_exactly_one_event(
        self, platform_admin: Any, django_capture_on_commit_callbacks: Any, events: Any
    ) -> None:
        with django_capture_on_commit_callbacks(execute=True):
            organization = _create(platform_admin)
        [row] = rows(action="organization.created")
        assert row.organization_id == organization.pk
        assert (row.actor_id, row.actor_email) == (platform_admin.pk, platform_admin.email)
        assert row.outcome == "success"
        [logged] = [e for e in events if e.name == "organization.created"]
        assert logged.metadata["audit_id"] == str(row.pk)

    def test_rollback_discards_mutation_and_event(
        self, platform_admin: Any, django_capture_on_commit_callbacks: Any, events: Any
    ) -> None:
        def create_then_fail() -> None:
            with transaction.atomic():
                _create(platform_admin)
                raise RuntimeError

        with django_capture_on_commit_callbacks(execute=True), pytest.raises(RuntimeError):
            create_then_fail()
        assert not Organization.objects.exists()
        assert rows(action="organization.created") == []
        assert "organization.created" not in [e.name for e in events]  # no misleading log

    def test_audit_failure_prevents_the_mutation(
        self, platform_admin: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def failing_save(*_args: Any, **_kwargs: Any) -> None:
            raise DatabaseError("audit storage unavailable")

        monkeypatch.setattr(AuditLog, "save", failing_save)
        with pytest.raises(DatabaseError, match="audit storage"):
            _create(platform_admin)
        assert not Organization.objects.exists()

    def test_invalid_audit_data_prevents_the_mutation(
        self, platform_admin: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        original = audit.record

        def with_bad_metadata(*args: Any, **kwargs: Any) -> Any:
            return original(*args, **{**kwargs, "metadata": {"unlisted": 1}})

        monkeypatch.setattr("apps.organizations.services.audit.record", with_bad_metadata)
        with pytest.raises(AuditDataError):
            _create(platform_admin)
        assert not Organization.objects.exists()

    def test_log_sink_failure_cannot_fail_a_committed_mutation(
        self, platform_admin: Any, django_capture_on_commit_callbacks: Any
    ) -> None:
        def broken(_event: Any) -> None:
            raise RuntimeError("log pipeline down")

        unregister = security_events.register_sink(broken)
        try:
            with django_capture_on_commit_callbacks(execute=True):
                organization = _create(platform_admin)
        finally:
            unregister()
        assert Organization.objects.filter(pk=organization.pk).exists()
        assert len(rows(action="organization.created")) == 1

    def test_invalid_outcome_is_rejected(self) -> None:
        with pytest.raises(AuditDataError):
            audit.record("test.event", outcome="maybe")  # type: ignore[arg-type]


@pytest.mark.django_db(transaction=True)
class TestTransactionBoundaries:
    def test_record_outside_a_transaction_is_refused(self) -> None:
        with pytest.raises(audit.AuditTransactionError):
            audit.record("test.unwrapped")
        assert rows(action="test.unwrapped") == []

    def test_security_event_inside_a_business_transaction_is_refused(self) -> None:
        with pytest.raises(RuntimeError), transaction.atomic():
            audit.record_security_event("test.nested")
        assert rows(action="test.nested") == []

    def test_security_event_survives_a_rolled_back_business_transaction(self) -> None:
        def business_then_fail() -> None:
            with transaction.atomic():
                AuditLog.objects.create(action="test.business", outcome="success")
                raise RuntimeError

        with pytest.raises(RuntimeError):
            business_then_fail()
        audit.record_security_event("test.failure_after_rollback")
        assert rows(action="test.business") == []
        assert len(rows(action="test.failure_after_rollback")) == 1

    def test_failed_login_is_recorded_independently(self, user: Any) -> None:
        response = Client().post(
            "/api/v1/auth/login/",
            {"email": user.email, "password": "wrong-password-value"},
            content_type="application/json",
        )
        assert response.status_code == 401
        [row] = rows(action="auth.login.failed")
        assert row.actor_id is None
        assert len(row.metadata["subject_digest"]) == 64


# ------------------------------------------------------------------------ request context
@pytest.mark.django_db
def test_request_context_is_captured_and_sanitized(user: Any) -> None:
    Client().post(
        "/api/v1/auth/login/",
        {"email": user.email, "password": "wrong-password-value"},
        content_type="application/json",
        HTTP_USER_AGENT=f"Probe/1.0\x00\x1b[31m password={SECRET} " + "x" * 400,
        HTTP_X_REQUEST_ID="req-1234-abcd",
    )
    [row] = rows(action="auth.login.failed")
    assert row.request_id == "req-1234-abcd"
    assert row.ip_address == "127.0.0.1"
    assert row.user_agent.startswith("Probe/1.0")
    assert len(row.user_agent) <= 256
    assert "\x00" not in row.user_agent
    assert "\x1b" not in row.user_agent
    assert SECRET not in row.user_agent


# ----------------------------------------------------------------------------- redaction
class TestRedaction:
    def test_unknown_metadata_keys_are_rejected(self) -> None:
        for key in ("unlisted", "password", "access_token", "authorization", "cookie", "csrf"):
            with pytest.raises(AuditDataError):
                clean_metadata({key: "value"})

    def test_sensitive_looking_allowlisted_keys_hold_identifiers_only(self) -> None:
        flagged = {key for key in METADATA_FIELDS if is_sensitive_key(key)}
        assert flagged == {"session_id", "previous_session_id", "token_user_id", "sessions_revoked"}
        with pytest.raises(AuditDataError):
            clean_metadata({"session_id": SECRET})
        with pytest.raises(AuditDataError):
            clean_metadata({"token_user_id": "eyJhbGciOi.payload.sig"})

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("locked_for_seconds", -1),
            ("locked_for_seconds", True),
            ("queued", "yes"),
            ("subject_digest", "not-a-digest"),
            ("scope", "has spaces"),
            ("changed_fields", ["ok"] * 21),
            ("outbox_id", "nope"),
        ],
    )
    def test_metadata_values_are_validated(self, key: str, value: Any) -> None:
        with pytest.raises(AuditDataError):
            clean_metadata({key: value})

    def test_text_is_scrubbed_and_bounded(self) -> None:
        cleaned = clean_metadata({"reason": f"bad\x00 password={SECRET} " + "y" * 500})
        assert SECRET not in cleaned["reason"]
        assert "\x00" not in cleaned["reason"]
        assert len(cleaned["reason"]) <= 200
        assert clean_metadata({"queued": None}) == {}

    def test_changes_are_allowlisted_and_passwords_never_valued(self) -> None:
        assert clean_changes("user", {"password": ("old-hash", "new-hash")}) == {
            "password": {"changed": True}
        }
        assert clean_changes("organization", {"name": ("A", "B")}) == {
            "name": {"from": "A", "to": "B"}
        }
        with pytest.raises(AuditDataError):
            clean_changes("organization", {"slug": ("a", "b")})
        with pytest.raises(AuditDataError):
            clean_changes("session", {"refresh_jti_hash": ("a", "b")})
        with pytest.raises(AuditDataError):
            clean_changes("organization", {"name": ({"nested": 1}, "B")})
        assert clean_changes("user", None) == {}

    def test_targets_are_validated(self) -> None:
        assert clean_target("", "ignored") == ("", "")
        assert clean_target("user", None) == ("user", "")
        assert clean_target("session", "x" * 100) == ("session", "x" * 64)
        with pytest.raises(AuditDataError):
            clean_target("Bad Type", "x")
