"""DRF exception handling producing RFC 9457 Problem Details.

Configured as ``REST_FRAMEWORK["EXCEPTION_HANDLER"]``. Delegates to DRF's default handler for
known API exceptions so standard headers (``WWW-Authenticate``, ``Retry-After``, ``Allow``) and
transaction rollback behave exactly as in DRF, then replaces the body with a Problem Details
document and sets ``Content-Type: application/problem+json``.

Client-safe message conventions (ADR-0009)
------------------------------------------
- **Domain errors** that need a specific client-facing message subclass :class:`DomainError`.
  Their messages must be static, human-readable and free of secrets, internal identifiers,
  SQL, file paths or exception text. Only ``DomainError`` messages are passed through (after a
  sanitization safety net).
- **Every other exception** gets a fixed, generic message chosen by type: built-in DRF exceptions
  (``ParseError``, ``AuthenticationFailed``, ``PermissionDenied``...), Django exceptions, and
  unexpected exceptions (500). Their own message text is never sent to clients.
- **Validation messages** (serializer and model validation) are field-level and intended for
  clients, but they must not echo submitted values. As a safety net, errors on sensitive fields
  (password, token, secret...) are replaced with a generic message, all messages are
  text-sanitized and length-capped, and the number of reported errors is capped.
"""

import re
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

import structlog
from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.core.exceptions import RequestDataTooBig, TooManyFieldsSent
from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import Http404
from rest_framework import exceptions, status
from rest_framework.response import Response
from rest_framework.serializers import as_serializer_error
from rest_framework.settings import api_settings
from rest_framework.views import exception_handler as drf_exception_handler
from rest_framework.views import set_rollback

from apps.core.problems import PROBLEM_CONTENT_TYPE, ProblemError, build_problem
from apps.core.sanitization import is_sensitive_key, sanitize_text

logger = structlog.get_logger(__name__)


class DomainError(exceptions.APIException):
    """Base class for errors whose message is deliberately written for API clients.

    Subclasses set ``status_code``, ``default_code`` and a static ``default_detail``. Never build
    messages from secrets, credentials, internal identifiers or exception text.
    """

    status_code: int = status.HTTP_400_BAD_REQUEST
    default_detail = "The request could not be completed."
    default_code = "domain_error"


class ConflictError(DomainError):
    """The request conflicts with the current state of the target resource (HTTP 409)."""

    status_code = status.HTTP_409_CONFLICT
    default_detail = "The request conflicts with the current state of the resource."
    default_code = "conflict"


class RequestTooLargeError(DomainError):
    """The request body exceeds ``DATA_UPLOAD_MAX_MEMORY_SIZE`` (HTTP 413, AEMS-019)."""

    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    default_detail = "The request body is too large."
    default_code = "request_too_large"


class InvalidQueryParameters(exceptions.ValidationError):
    """Query-string validation failure; errors are keyed by parameter name."""

    default_detail = "One or more query parameters are invalid."
    default_code = "invalid_query_parameters"


MAX_REPORTED_ERRORS = 100
MAX_MESSAGE_LENGTH = 300
SENSITIVE_FIELD_MESSAGE = "This value is invalid."

_VALIDATION_DETAIL = "The request contains invalid data."
_QUERY_VALIDATION_DETAIL = "One or more query parameters are invalid."
_INTERNAL_ERROR_DETAIL = "An unexpected error occurred."
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

# Fixed client messages for non-domain exceptions, most specific class first.
_GENERIC_DETAILS: tuple[tuple[type[exceptions.APIException], str], ...] = (
    (exceptions.ParseError, "The request body could not be parsed."),
    (exceptions.AuthenticationFailed, "Authentication credentials were invalid."),
    (exceptions.NotAuthenticated, "Authentication credentials were not provided."),
    (exceptions.PermissionDenied, "You do not have permission to perform this action."),
    (exceptions.NotFound, "The requested resource was not found."),
    (exceptions.MethodNotAllowed, "The request method is not allowed for this resource."),
    (exceptions.NotAcceptable, "The requested response format is not supported."),
    (exceptions.UnsupportedMediaType, "The request content type is not supported."),
    (exceptions.Throttled, "Too many requests. Retry after the time given in Retry-After."),
)
_FALLBACK_DETAIL = "The request could not be completed."


def _client_text(text: str) -> str:
    text = sanitize_text(text)
    if len(text) > MAX_MESSAGE_LENGTH:
        text = text[: MAX_MESSAGE_LENGTH - 3] + "..."
    return text


def _safe_code(code: object, default: str) -> str:
    value = str(code) if code is not None else ""
    return value if _SAFE_CODE.fullmatch(value) else default


def _escape_pointer_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _iter_error_leaves(
    detail: Any, path: tuple[str, ...]
) -> Iterator[tuple[tuple[str, ...], exceptions.ErrorDetail | str]]:
    """Yield (path, error) pairs from a nested DRF validation ``detail`` structure."""
    if isinstance(detail, Mapping):
        for key, value in detail.items():
            key_str = str(key)
            child = path if key_str == api_settings.NON_FIELD_ERRORS_KEY else (*path, key_str)
            yield from _iter_error_leaves(value, child)
    elif isinstance(detail, Sequence) and not isinstance(detail, str):
        for index, item in enumerate(detail):
            if isinstance(item, Mapping | list | tuple):
                yield from _iter_error_leaves(item, (*path, str(index)))
            else:
                yield path, item
    else:
        yield path, detail


def flatten_validation_errors(detail: Any, *, query_parameters: bool) -> list[ProblemError]:
    """Convert DRF validation details to Problem Details ``errors`` entries.

    Body errors carry an RFC 6901 JSON Pointer in URI-fragment form (``#/field/0/child``; ``#``
    for non-field errors). Query-parameter errors carry the ``parameter`` name instead.
    Messages on sensitive fields are replaced, all messages are sanitized and capped, and at most
    :data:`MAX_REPORTED_ERRORS` entries are returned.
    """
    errors: list[ProblemError] = []
    for path, leaf in _iter_error_leaves(detail, ()):
        if len(errors) >= MAX_REPORTED_ERRORS:
            break
        sensitive = any(is_sensitive_key(segment) for segment in path)
        item: ProblemError = {
            "detail": SENSITIVE_FIELD_MESSAGE if sensitive else _client_text(str(leaf)),
            "code": _safe_code(getattr(leaf, "code", None), "invalid"),
        }
        if query_parameters:
            item["parameter"] = ".".join(path)
        else:
            item["pointer"] = "#" + "".join(f"/{_escape_pointer_token(p)}" for p in path)
        errors.append(item)
    return errors


def _translate_django_exception(exc: Exception) -> Exception:
    """Map Django exceptions to DRF ones (their messages are never forwarded)."""
    if isinstance(exc, Http404):
        return exceptions.NotFound()
    if isinstance(exc, DjangoPermissionDenied):
        return exceptions.PermissionDenied()
    if isinstance(exc, DjangoValidationError):
        return exceptions.ValidationError(detail=as_serializer_error(exc))
    if isinstance(exc, (RequestDataTooBig, TooManyFieldsSent)):
        # Django's request-size limits are client errors, not server faults (AEMS-019).
        return RequestTooLargeError()
    return exc


def _problem_code(exc: exceptions.APIException) -> str:
    if isinstance(exc, InvalidQueryParameters):
        return InvalidQueryParameters.default_code
    if isinstance(exc, exceptions.ValidationError):
        return "validation_error"
    code = exc.default_code
    return "api_error" if code == "error" else _safe_code(code, "api_error")


def _problem_detail(exc: exceptions.APIException) -> str:
    if isinstance(exc, InvalidQueryParameters):
        return _QUERY_VALIDATION_DETAIL
    if isinstance(exc, exceptions.ValidationError):
        return _VALIDATION_DETAIL
    if isinstance(exc, DomainError):
        detail = exc.detail if isinstance(exc.detail, str) else exc.default_detail
        return _client_text(str(detail))
    for exception_type, message in _GENERIC_DETAILS:
        if isinstance(exc, exception_type):
            return message
    return _FALLBACK_DETAIL


def problem_exception_handler(exc: Exception, context: dict[str, Any]) -> Response:
    exc = _translate_django_exception(exc)

    if not isinstance(exc, exceptions.APIException):
        view = context.get("view")
        # The traceback (without local variables) is rendered and sanitized by the logging
        # formatter; nothing about the exception reaches the client.
        logger.error(
            "request.unhandled_exception",
            view=type(view).__name__ if view is not None else None,
            exc_info=exc,
        )
        set_rollback()
        return Response(
            build_problem(status=500, code="internal_error", detail=_INTERNAL_ERROR_DETAIL),
            status=500,
            content_type=PROBLEM_CONTENT_TYPE,
        )

    response = drf_exception_handler(exc, context)
    if response is None:  # pragma: no cover - DRF handles every APIException
        response = Response(status=exc.status_code)

    errors = None
    if isinstance(exc, exceptions.ValidationError):
        errors = flatten_validation_errors(
            exc.detail, query_parameters=isinstance(exc, InvalidQueryParameters)
        )

    response.data = build_problem(
        status=response.status_code,
        code=_problem_code(exc),
        detail=_problem_detail(exc),
        errors=errors,
    )
    response.content_type = PROBLEM_CONTENT_TYPE
    return response
