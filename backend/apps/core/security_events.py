"""Security event interface (ADR-0013).

A narrow, stable interface through which security-relevant actions are reported. Batch 3 records
events as structured log entries (logger ``aems.security``). Batch 5 adds durable, transactional
persistence (``AuditLog``) behind the same interface **without changing call sites**.

Conventions
-----------
- Event names are dotted, lowercase, past tense: ``auth.login.succeeded``,
  ``auth.refresh.reuse_detected``. ``outcome`` is ``"success"`` or ``"failure"``.
- Events carry identifiers, never secrets or raw personal data: ``user_id``, ``session_id``,
  ``client_ip`` and an optional ``subject_digest`` (HMAC of an identifier such as a submitted email
  for unknown accounts). Passwords, tokens and hashes are never included (they are also redacted by
  the logging pipeline as a safety net).
- **Mutation events** (something changed: login session created, password changed, session revoked)
  use :func:`record_after_commit` so an event is only emitted if the change committed.
- **Security/failure events** (failed login, rate limiting, refresh replay) use
  :func:`record_security_event` and are emitted immediately, outside any business transaction, so a
  rollback can never discard them (ADR-0006). Replay detection commits its revocation first and only
  then records the event.

Not yet implemented (Batch 5): durable persistence. Until then events exist only in logs; nothing in
Batch 3 claims an audit record is stored.
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
    """Add a sink (Batch 5: durable audit persistence; tests: capture). Returns an unregister."""
    _SINKS.append(sink)
    return lambda: _SINKS.remove(sink)


def _emit(event: SecurityEvent) -> None:
    for sink in list(_SINKS):
        sink(event)


def _build(name: str, outcome: Outcome, **fields: Any) -> SecurityEvent:
    known = {
        k: fields.pop(k, None) for k in ("user_id", "session_id", "client_ip", "subject_digest")
    }
    return SecurityEvent(
        name=name,
        outcome=outcome,
        **{k: (str(v) if v is not None else None) for k, v in known.items()},
        metadata=fields,
    )


def record_security_event(name: str, *, outcome: Outcome, **fields: Any) -> None:
    """Emit immediately (failures, rate limiting, replay detection after its commit)."""
    _emit(_build(name, outcome, **fields))


def record_after_commit(name: str, *, outcome: Outcome = "success", **fields: Any) -> None:
    """Emit once the surrounding transaction commits (dropped if it rolls back)."""
    event = _build(name, outcome, **fields)
    transaction.on_commit(lambda: _emit(event))
