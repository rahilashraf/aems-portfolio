"""Audit allowlists and sanitization (ADR-0006 "Redaction", ADR-0016).

Nothing supplied by a caller is copied into an audit row as-is:

- ``metadata`` keys must be listed in :data:`METADATA_FIELDS`, each with a validator that enforces
  type and size. Unknown keys raise :class:`AuditDataError` (a programming error, caught by
  tests) instead of being stored. Keys that look sensitive (password, token, secret, cookie,
  authorization, ...) are rejected even if someone adds them to the allowlist.
- ``changes`` may only name fields listed for the target type in :data:`CHANGE_FIELDS`.
  Fields in :data:`SENSITIVE_CHANGE_FIELDS` (passwords) are recorded as ``{"changed": true}``,
  never with values.
- Every string is scrubbed with the shared text sanitizer, stripped of control characters and
  bounded.

So passwords, hashes, access/refresh tokens, reset or invitation tokens (raw or hashed), JWT keys,
CSRF tokens, cookies, authorization headers and request bodies cannot reach the audit table
through this layer.
"""

import re
import uuid
from collections.abc import Callable, Mapping
from typing import Any

from apps.core.sanitization import is_sensitive_key, sanitize_text

MAX_TEXT = 200
MAX_LIST_ITEMS = 20


class AuditDataError(ValueError):
    """Audit data that is not allowlisted or not valid. Never stored."""


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        msg = "Expected text."
        raise AuditDataError(msg)
    cleaned = "".join(ch for ch in value if ch.isprintable())
    return sanitize_text(cleaned)[:limit]


def _identifier(value: Any) -> str:
    """Short machine identifier (scope, category, reason code, status)."""
    text = _text(str(value) if not isinstance(value, str) else value, 64)
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", text):
        msg = "Expected an identifier."
        raise AuditDataError(msg)
    return text


def _uuid(value: Any) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (TypeError, ValueError) as exc:
        msg = "Expected a UUID."
        raise AuditDataError(msg) from exc


def _hex_digest(value: Any) -> str:
    text = str(value)
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        msg = "Expected a SHA-256 hex digest."
        raise AuditDataError(msg)
    return text


def _non_negative_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        msg = "Expected a non-negative integer."
        raise AuditDataError(msg)
    return int(value)


def _bool(value: Any) -> bool:
    if not isinstance(value, bool):
        msg = "Expected a boolean."
        raise AuditDataError(msg)
    return value


def _identifier_list(value: Any) -> list[str]:
    if not isinstance(value, list | tuple) or len(value) > MAX_LIST_ITEMS:
        msg = f"Expected a list of at most {MAX_LIST_ITEMS} identifiers."
        raise AuditDataError(msg)
    return [_identifier(item) for item in value]


def _uuid_list(value: Any) -> list[str]:
    if not isinstance(value, list | tuple) or len(value) > MAX_LIST_ITEMS:
        msg = f"Expected a list of at most {MAX_LIST_ITEMS} UUIDs."
        raise AuditDataError(msg)
    return [_uuid(item) for item in value]


def _reason(value: Any) -> str:
    return _text(str(value))


Validator = Callable[[Any], Any]

#: Every metadata key an audit event may carry.
METADATA_FIELDS: dict[str, Validator] = {
    "scope": _identifier,
    "subject_digest": _hex_digest,
    "locked_for_seconds": _non_negative_int,
    "session_id": _uuid,
    "previous_session_id": _uuid,
    "queued": _bool,
    "error_type": _identifier,
    "reason": _reason,
    "count": _non_negative_int,
    "sessions_revoked": _non_negative_int,
    "token_user_id": _uuid,
    "revoked": _bool,
    "changed_fields": _identifier_list,
    "previous_status": _identifier,
    "status": _identifier,
    "outbox_id": _uuid,
    "attempt": _non_negative_int,
    "category": _identifier,
    "retry_scheduled": _bool,
    # RBAC (Batch 6): identifiers and catalog codes only.
    "member_user_id": _uuid,
    "roles_added": _uuid_list,
    "roles_removed": _uuid_list,
    "permissions_added": _identifier_list,
    "permissions_removed": _identifier_list,
    # Invitations (Batch 7): identifiers and flags only, never addresses or tokens.
    "invitation_id": _uuid,
    "initial_owner": _bool,
    "account_created": _bool,
}

#: Fields whose changes may be recorded, per target type.
CHANGE_FIELDS: dict[str, frozenset[str]] = {
    "organization": frozenset({"name", "organization_type", "timezone", "status"}),
    "user": frozenset({"full_name", "is_active", "is_staff", "is_superuser", "password"}),
    "role": frozenset({"name", "description"}),
    "membership": frozenset({"status"}),
}
#: Recorded as {"changed": true}: the values never reach the audit table.
SENSITIVE_CHANGE_FIELDS = frozenset({"password"})

_SAFE_CHANGE_VALUE = (str, int, bool, type(None))


def clean_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for key, value in (metadata or {}).items():
        validator = METADATA_FIELDS.get(key)
        if validator is None or (is_sensitive_key(key) and key not in _SENSITIVE_LOOKING_ALLOWED):
            msg = f"Metadata key {key!r} is not allowlisted for audit records."
            raise AuditDataError(msg)
        if value is None:
            continue
        cleaned[key] = validator(value)
    return cleaned


# Allowlisted keys that merely *contain* a sensitive-looking word but hold identifiers only.
_SENSITIVE_LOOKING_ALLOWED = frozenset(
    {"session_id", "previous_session_id", "token_user_id", "sessions_revoked"}
)


def clean_changes(
    target_type: str, changes: Mapping[str, tuple[Any, Any]] | None
) -> dict[str, Any]:
    if not changes:
        return {}
    allowed = CHANGE_FIELDS.get(target_type, frozenset())
    cleaned: dict[str, Any] = {}
    for field_name, values in changes.items():
        if field_name not in allowed:
            msg = f"Changes to {target_type}.{field_name} are not allowlisted for audit records."
            raise AuditDataError(msg)
        if field_name in SENSITIVE_CHANGE_FIELDS:
            cleaned[field_name] = {"changed": True}
            continue
        before, after = values
        cleaned[field_name] = {"from": _change_value(before), "to": _change_value(after)}
    return cleaned


def _change_value(value: Any) -> Any:
    if not isinstance(value, _SAFE_CHANGE_VALUE):
        msg = "Change values must be text, numbers, booleans or null."
        raise AuditDataError(msg)
    return _text(value) if isinstance(value, str) else value


def clean_target(target_type: str, target_id: Any) -> tuple[str, str]:
    if not target_type:
        return "", ""
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", target_type):
        msg = "Invalid audit target type."
        raise AuditDataError(msg)
    target = _text(str(target_id), 64) if target_id not in (None, "") else ""
    return target_type, target
