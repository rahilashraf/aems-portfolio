"""Per-request context: request IDs and log-context binding.

The request context is stored in :mod:`contextvars` (via ``structlog.contextvars``), which isolates
values per thread and per asyncio task, so concurrent requests never observe each other's IDs.
The request middleware clears the context at the start and end of every request.

Future integration (not implemented yet): Batch 3 will bind ``user_id`` after authentication
and Batch 4 will bind ``organization_id`` after tenant resolution, both via
:func:`bind_request_context`, so every log line emitted while handling the request carries them.
"""

import re
import uuid
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

import structlog

REQUEST_ID_HEADER = "X-Request-ID"
REQUEST_ID_META_KEY = "HTTP_X_REQUEST_ID"
REQUEST_ID_MIN_LENGTH = 8
REQUEST_ID_MAX_LENGTH = 128

# Conservative character set: safe to echo in headers and logs (no whitespace, quotes, control
# characters or separators that could enable header or log injection).
_VALID_REQUEST_ID = re.compile(
    rf"^[A-Za-z0-9][A-Za-z0-9._:-]{{{REQUEST_ID_MIN_LENGTH - 1},{REQUEST_ID_MAX_LENGTH - 1}}}$"
)


def is_valid_request_id(value: str | None) -> bool:
    """Return True if a client-supplied request ID is acceptable to propagate."""
    return value is not None and _VALID_REQUEST_ID.fullmatch(value) is not None


def generate_request_id() -> str:
    """Return a new random request ID (UUIDv4, canonical form)."""
    return str(uuid.uuid4())


def resolve_request_id(supplied: str | None) -> str:
    """Use the supplied ID if valid, otherwise generate a fresh one."""
    return (
        supplied
        if supplied is not None and is_valid_request_id(supplied)
        else generate_request_id()
    )


def bind_request_context(**values: Any) -> None:
    """Bind values to the current request's log context."""
    structlog.contextvars.bind_contextvars(**values)


def clear_request_context() -> None:
    """Remove all request-scoped context values."""
    structlog.contextvars.clear_contextvars()
    _request_meta.set(None)


def clear_request_context_on_request_finished(sender: Any, **kwargs: Any) -> None:
    """``request_finished`` receiver: the response has been closed, end the request context."""
    clear_request_context()


def get_request_id() -> str | None:
    """Return the current request ID, or None outside a request."""
    value = structlog.contextvars.get_contextvars().get("request_id")
    return value if isinstance(value, str) else None


# ----------------------------------------------------------------------- request metadata
@dataclass(frozen=True)
class RequestMeta:
    """Client details of the current request, for audit records (never added to every log line).

    ``client_ip`` follows the trusted-proxy rules of :func:`apps.core.net.client_ip`;
    ``user_agent`` is sanitized and truncated by the middleware.
    """

    client_ip: str | None
    user_agent: str


_request_meta: ContextVar[RequestMeta | None] = ContextVar("aems_request_meta", default=None)


def bind_request_meta(meta: RequestMeta) -> None:
    _request_meta.set(meta)


def get_request_meta() -> RequestMeta | None:
    return _request_meta.get()
