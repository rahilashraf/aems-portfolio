"""Structured security logging (``aems.security``): the operational log of audited events.

This module only **logs**. Durable, queryable audit records are written by the audit service
(:mod:`apps.audit.services`, ADR-0016), which calls :func:`emit_after_commit` or :func:`emit` once
its row is safely stored. The log is never the system of record, so:

- every entry corresponds to at most one audit row (there is no persistence sink here, so nothing
  can be written twice);
- logging can never fail the caller: sink errors are caught and reported, and a committed mutation
  is never turned into an HTTP error by a logging problem;
- :func:`log_security_event` is for operational events that are deliberately **not** persisted
  (high-volume, no state change), e.g. ``auth.refresh.rotated``.

Conventions: dotted, past-tense names; ``outcome`` is ``"success"`` or ``"failure"``; identifiers
only, never secrets (the logging pipeline redacts sensitive keys as a safety net).
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

import structlog
from django.db import transaction

Outcome = Literal["success", "failure"]

_logger = structlog.get_logger("aems.security")


@dataclass(frozen=True)
class SecurityEvent:
    name: str
    outcome: Outcome
    user_id: str | None = None
    session_id: str | None = None
    client_ip: str | None = None
    subject_digest: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


SecurityEventSink = Callable[[SecurityEvent], None]


def log_sink(event: SecurityEvent) -> None:
    log = _logger.info if event.outcome == "success" else _logger.warning
    log(
        event.name,
        outcome=event.outcome,
        user_id=event.user_id,
        session_id=event.session_id,
        client_ip=event.client_ip,
        subject_digest=event.subject_digest,
        **event.metadata,
    )


_SINKS: list[SecurityEventSink] = [log_sink]


def register_sink(sink: SecurityEventSink) -> Callable[[], None]:
    """Add an observer (tests capture events this way). Returns an unregister function."""
    _SINKS.append(sink)
    return lambda: _SINKS.remove(sink)


def emit(event: SecurityEvent) -> None:
    """Deliver an event to every sink now. Never raises."""
    for sink in list(_SINKS):
        try:
            sink(event)
        except Exception as exc:  # logging must never fail the caller
            _logger.error(
                "security.sink_failed",
                event_name=event.name,
                sink=getattr(sink, "__qualname__", type(sink).__name__),
                error_type=type(exc).__name__,
            )


def emit_after_commit(event: SecurityEvent) -> None:
    """Deliver once the surrounding transaction commits (dropped if it rolls back)."""
    transaction.on_commit(lambda: emit(event))


def build_event(name: str, outcome: Outcome, **fields: Any) -> SecurityEvent:
    known = {
        k: fields.pop(k, None) for k in ("user_id", "session_id", "client_ip", "subject_digest")
    }
    return SecurityEvent(
        name=name,
        outcome=outcome,
        **{k: (str(v) if v is not None else None) for k, v in known.items()},
        metadata=fields,
    )


def log_security_event(name: str, *, outcome: Outcome, **fields: Any) -> None:
    """Log an operational event immediately **without** an audit record."""
    emit(build_event(name, outcome, **fields))
