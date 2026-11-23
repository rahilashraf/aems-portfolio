"""Writing audit records (ADR-0006, ADR-0016).

Two entry points, two lifecycles:

:func:`record` - **transactional mutation events**
    Call it inside the ``transaction.atomic()`` block that performs the mutation. The audit row is
    part of that transaction: if the mutation rolls back, so does the event; if the audit insert
    fails, the exception propagates and the mutation does not commit. Calling it outside a
    transaction raises :class:`AuditTransactionError`, so a mutation can never commit without its
    event by accident. The structured log entry is emitted only after the commit.

:func:`record_security_event` - **independent security events**
    Failed logins, rate limiting, invalid tokens, CSRF failures, denied tenant access and similar
    events that must be kept even though nothing (or something else) was committed. The row is
    written in its **own** short transaction, ``transaction.atomic(durable=True)``, so Django
    raises ``RuntimeError`` if a caller is still inside a transaction (including one marked for
    rollback): callers record these events after their business transaction has ended, never from
    inside it. The structured log entry follows the commit.

Both validate and sanitize everything through :mod:`apps.audit.redaction`, take the request ID,
client IP and user agent from the current request context, and snapshot the actor's email from
the user row (never from client input). Neither ever writes the same event twice: the structured
log is an observer, not a second store.
"""

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from django.db import connection, transaction

from apps.core.request_context import get_request_id, get_request_meta
from apps.core.security_events import Outcome, build_event, emit, emit_after_commit

from .models import AuditLog, AuditOutcome
from .redaction import AuditDataError, clean_changes, clean_metadata, clean_target

if TYPE_CHECKING:
    from apps.accounts.models import User
    from apps.organizations.models import Organization

__all__ = ["AuditDataError", "AuditTransactionError", "record", "record_security_event"]


class AuditTransactionError(RuntimeError):
    """``record()`` was called outside the business transaction it belongs to."""


def record(
    action: str,
    *,
    outcome: Outcome = "success",
    actor: "User | None" = None,
    organization: "Organization | None" = None,
    target_type: str = "",
    target_id: Any = "",
    changes: Mapping[str, tuple[Any, Any]] | None = None,
    metadata: Mapping[str, Any] | None = None,
    client_ip: str | None = None,
) -> AuditLog:
    """Record a mutation event inside the caller's transaction (see the module docs)."""
    if not connection.in_atomic_block:
        msg = (
            f"audit.record({action!r}) must run inside the transaction that performs the mutation."
        )
        raise AuditTransactionError(msg)
    entry = _insert(
        action,
        outcome=outcome,
        actor=actor,
        organization=organization,
        target_type=target_type,
        target_id=target_id,
        changes=changes,
        metadata=metadata,
        client_ip=client_ip,
    )
    emit_after_commit(_log_event(entry))
    return entry


def record_security_event(
    action: str,
    *,
    outcome: Outcome = "failure",
    actor: "User | None" = None,
    organization: "Organization | None" = None,
    target_type: str = "",
    target_id: Any = "",
    metadata: Mapping[str, Any] | None = None,
    client_ip: str | None = None,
) -> AuditLog:
    """Record an independent security event in its own transaction (see the module docs)."""
    with transaction.atomic(durable=True):
        entry = _insert(
            action,
            outcome=outcome,
            actor=actor,
            organization=organization,
            target_type=target_type,
            target_id=target_id,
            changes=None,
            metadata=metadata,
            client_ip=client_ip,
        )
    emit(_log_event(entry))
    return entry


def _insert(
    action: str,
    *,
    outcome: Outcome,
    actor: "User | None",
    organization: "Organization | None",
    target_type: str,
    target_id: Any,
    changes: Mapping[str, tuple[Any, Any]] | None,
    metadata: Mapping[str, Any] | None,
    client_ip: str | None,
) -> AuditLog:
    if outcome not in AuditOutcome.values:
        msg = f"Invalid audit outcome {outcome!r}."
        raise AuditDataError(msg)
    target_type, target_id = clean_target(target_type, target_id)
    meta = get_request_meta()
    entry = AuditLog(
        organization=organization,
        actor=actor,
        actor_email=(actor.email if actor is not None else ""),
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=target_id,
        changes=clean_changes(target_type, changes),
        metadata=clean_metadata(metadata),
        ip_address=client_ip or (meta.client_ip if meta else None),
        user_agent=meta.user_agent if meta else "",
        request_id=get_request_id() or "",
    )
    entry.full_clean(validate_unique=False, validate_constraints=False)
    entry.save(force_insert=True)
    return entry


def _log_event(entry: AuditLog) -> Any:
    fields: dict[str, Any] = dict(entry.metadata)
    session_id = fields.pop("session_id", None)
    subject_digest = fields.pop("subject_digest", None)
    if entry.organization_id is not None:
        fields["organization_id"] = str(entry.organization_id)
    if entry.target_type:
        fields["target_type"] = entry.target_type
        fields["target_id"] = entry.target_id
    if entry.changes:
        fields["changed_fields"] = sorted(entry.changes)
    return build_event(
        entry.action,
        entry.outcome,  # type: ignore[arg-type]
        user_id=entry.actor_id,
        session_id=session_id,
        client_ip=entry.ip_address,
        subject_digest=subject_digest,
        audit_id=str(entry.id),
        **fields,
    )
