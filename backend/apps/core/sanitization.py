"""Bounded, cycle-safe redaction of sensitive data (used by logging and error handling).

Two layers:

- **Structural redaction** (:func:`redact_structure`): values stored under sensitive keys
  (password, token, secret, cookie, authorization, ...) are replaced with ``[REDACTED]`` in nested
  mappings and sequences. Traversal is bounded: past :data:`MAX_DEPTH` a value is replaced with
  ``[TRUNCATED]`` (never returned unredacted), containers are capped at :data:`MAX_ITEMS` entries,
  the total number of visited nodes is capped at :data:`MAX_NODES`, and circular references become
  ``[CIRCULAR]``. Redaction can therefore never recurse infinitely or consume unbounded resources.
- **Text sanitization** (:func:`sanitize_text`): free text such as exception messages and rendered
  tracebacks is scrubbed of credentials in URLs (``scheme://user:pass@``), ``key=value`` /
  ``key: value`` pairs for sensitive keys, ``Bearer``/``Basic`` credentials, JWT-shaped tokens,
  URL query strings, PostgreSQL ``Key (col)=(value)`` details and quoted SQL literals on
  ``LINE n:`` error lines. Text is also length-capped.

These are safety nets. Code must still never deliberately log or return secrets.
"""

import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"
TRUNCATED = "[TRUNCATED]"
CIRCULAR = "[CIRCULAR]"

MAX_DEPTH = 8
MAX_ITEMS = 100
MAX_NODES = 2_000
MAX_TEXT_LENGTH = 8_192

SENSITIVE_KEY_PATTERN = re.compile(
    r"pass(word|wd|phrase)?|pwd|secret|token|authorization|auth_header|cookie|session|csrf"
    r"|api[_-]?key|credential|signature|private[_-]?key|dsn|database_url",
    re.IGNORECASE,
)

_SENSITIVE_NAMES = (
    r"password|passwd|pwd|passphrase|secret|client[_-]?secret|token|access[_-]?token"
    r"|refresh[_-]?token|id[_-]?token|api[_-]?key|apikey|authorization|cookie|sessionid"
    r"|session[_-]?id|csrftoken|csrf[_-]?token|signature|private[_-]?key"
)

_TEXT_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    # scheme://user:password@host  ->  scheme://user:[REDACTED]@host
    (
        re.compile(r"\b([a-z][a-z0-9+.\-]*://[^\s:/@'\"]*):([^\s@/'\"]+)@", re.IGNORECASE),
        rf"\1:{REDACTED}@",
    ),
    # Authorization schemes
    (
        re.compile(r"\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=\-]{6,}", re.IGNORECASE),
        rf"\1 {REDACTED}",
    ),
    # JWT-shaped values
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}"), REDACTED),
    # Query strings of absolute URLs
    (re.compile(r"\b(https?://[^\s?#'\"]+)\?[^\s#'\"]*", re.IGNORECASE), rf"\1?{REDACTED}"),
    # key=value / key: value / "key": "value" for sensitive names
    (
        re.compile(
            rf"(?P<key>[\"']?\b(?:{_SENSITIVE_NAMES})\b[\"']?)(?P<sep>\s*[=:]\s*)"
            r"(?P<quote>[\"']?)(?P<value>[^\s\"',;&)}\]]+)",
            re.IGNORECASE,
        ),
        rf"\g<key>\g<sep>\g<quote>{REDACTED}",
    ),
    # PostgreSQL constraint details: Key (email)=(someone@example.org) already exists.
    (re.compile(r"(Key \([^)]*\)=\()[^)]*(\))"), rf"\1{REDACTED}\2"),
)
_SQL_LINE = re.compile(r"^(\s*LINE \d+:.*)$", re.MULTILINE)
_SQL_LITERAL = re.compile(r"'(?:[^']|'')*'")


def sanitize_text(text: str) -> str:
    """Scrub credentials and sensitive literals from free text; cap its length."""
    if len(text) > MAX_TEXT_LENGTH:
        text = text[:MAX_TEXT_LENGTH] + f"... {TRUNCATED}"
    for pattern, replacement in _TEXT_RULES:
        text = pattern.sub(replacement, text)
    return _SQL_LINE.sub(lambda m: _SQL_LITERAL.sub(f"'{REDACTED}'", m.group(1)), text)


def is_sensitive_key(key: object) -> bool:
    return isinstance(key, str) and SENSITIVE_KEY_PATTERN.search(key) is not None


class _Budget:
    __slots__ = ("remaining",)

    def __init__(self, nodes: int) -> None:
        self.remaining = nodes


def redact_structure(value: Any, *, sanitize_strings: bool = True) -> Any:
    """Return a redacted copy of ``value`` (bounded and cycle-safe)."""
    return _redact(
        value, depth=0, ancestors=frozenset(), budget=_Budget(MAX_NODES), sanitize=sanitize_strings
    )


def _redact(  # noqa: PLR0911 - one early return per bounded/terminal case
    value: Any, *, depth: int, ancestors: frozenset[int], budget: _Budget, sanitize: bool
) -> Any:
    budget.remaining -= 1
    if budget.remaining < 0:
        return TRUNCATED
    if isinstance(value, str):
        return sanitize_text(value) if sanitize else value
    if not isinstance(value, Mapping | list | tuple | set | frozenset):
        return value
    if depth >= MAX_DEPTH:
        return TRUNCATED
    identity = id(value)
    if identity in ancestors:
        return CIRCULAR
    inner = ancestors | {identity}

    if isinstance(value, Mapping):
        result: dict[Any, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_ITEMS:
                result[TRUNCATED] = f"{len(value) - MAX_ITEMS} more entries"
                break
            result[key] = (
                REDACTED
                if is_sensitive_key(key)
                else _redact(
                    item, depth=depth + 1, ancestors=inner, budget=budget, sanitize=sanitize
                )
            )
        return result

    items: list[Any] = []
    for index, item in enumerate(value):
        if index >= MAX_ITEMS:
            items.append(f"{TRUNCATED} {len(value) - MAX_ITEMS} more items")
            break
        items.append(
            _redact(item, depth=depth + 1, ancestors=inner, budget=budget, sanitize=sanitize)
        )
    return tuple(items) if isinstance(value, tuple) else items
