"""DRF exception handling producing RFC 9457 Problem Details.

Configured as ``REST_FRAMEWORK["EXCEPTION_HANDLER"]``. Delegates to DRF's default handler for
known API exceptions so standard headers (``WWW-Authenticate``, ``Retry-After``, ``Allow``) and
transaction rollback behave exactly as in DRF, then replaces the body with a Problem Details
document and sets ``Content-Type: application/problem+json``.
"""

from collections.abc import Iterator, Mapping, Sequence
from typing import Any

import structlog
from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import Http404
from rest_framework import exceptions, status
from rest_framework.response import Response
from rest_framework.serializers import as_serializer_error
from rest_framework.settings import api_settings
from rest_framework.views import exception_handler as drf_exception_handler
from rest_framework.views import set_rollback

from apps.core.problems import PROBLEM_CONTENT_TYPE, ProblemError, build_problem

logger = structlog.get_logger(__name__)


class ConflictError(exceptions.APIException):
    """The request conflicts with the current state of the target resource (HTTP 409)."""

    status_code = status.HTTP_409_CONFLICT
    default_detail = "The request conflicts with the current state of the resource."
    default_code = "conflict"


class InvalidQueryParameters(exceptions.ValidationError):
    """Query-string validation failure; errors are keyed by parameter name."""

    default_detail = "One or more query parameters are invalid."
    default_code = "invalid_query_parameters"


_VALIDATION_DETAIL = "The request contains invalid data."
_QUERY_VALIDATION_DETAIL = "One or more query parameters are invalid."
_INTERNAL_ERROR_DETAIL = "An unexpected error occurred."


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
    """
    errors: list[ProblemError] = []
    for path, leaf in _iter_error_leaves(detail, ()):
        item: ProblemError = {
            "detail": str(leaf),
            "code": str(getattr(leaf, "code", None) or "invalid"),
        }
        if query_parameters:
            item["parameter"] = ".".join(path)
        else:
            item["pointer"] = "#" + "".join(f"/{_escape_pointer_token(p)}" for p in path)
        errors.append(item)
    return errors


def _translate_django_exception(exc: Exception) -> Exception:
    """Map Django exceptions to DRF ones with client-safe, generic messages."""
    if isinstance(exc, Http404):
        # Http404 messages can name models or lookups ("No X matches the given query.").
        return exceptions.NotFound()
    if isinstance(exc, DjangoPermissionDenied):
        return exceptions.PermissionDenied()
    if isinstance(exc, DjangoValidationError):
        return exceptions.ValidationError(detail=as_serializer_error(exc))
    return exc


def _problem_code(exc: exceptions.APIException) -> str:
    if isinstance(exc, InvalidQueryParameters):
        return InvalidQueryParameters.default_code
    if isinstance(exc, exceptions.ValidationError):
        return "validation_error"
    code = exc.default_code
    return "api_error" if code == "error" else str(code)


def _problem_detail(exc: exceptions.APIException) -> str:
    if isinstance(exc, InvalidQueryParameters):
        return _QUERY_VALIDATION_DETAIL
    if isinstance(exc, exceptions.ValidationError):
        return _VALIDATION_DETAIL
    if isinstance(exc.detail, str):
        return str(exc.detail)
    return str(exc.default_detail)


def problem_exception_handler(exc: Exception, context: dict[str, Any]) -> Response:
    exc = _translate_django_exception(exc)

    if not isinstance(exc, exceptions.APIException):
        view = context.get("view")
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
