"""RFC 9457 Problem Details: shared builders used by DRF and plain Django error handling.

Response members (see docs/adr/0009-api-error-response-conventions.md):

- ``type``: ``"about:blank"`` — the problem is fully described by the HTTP status; AEMS-specific
  semantics are carried by the stable ``code`` extension member.
- ``title``: the HTTP status phrase (required by RFC 9457 when ``type`` is ``about:blank``).
- ``status``: the HTTP status code.
- ``detail``: a human-readable, client-safe explanation (never exception internals).
- ``code``: stable, machine-readable application error code.
- ``request_id``: correlation ID, also returned in the ``X-Request-ID`` header.
- ``errors`` (optional): field- or parameter-level validation errors.
"""

from http import HTTPStatus
from typing import Any, NotRequired, TypedDict

from django.http import JsonResponse

from .request_context import get_request_id

PROBLEM_CONTENT_TYPE = "application/problem+json"
PROBLEM_TYPE_BLANK = "about:blank"


class ProblemError(TypedDict):
    detail: str
    code: str
    pointer: NotRequired[str]
    parameter: NotRequired[str]


class Problem(TypedDict):
    type: str
    title: str
    status: int
    detail: str
    code: str
    request_id: str | None
    errors: NotRequired[list[ProblemError]]


def build_problem(
    *,
    status: int,
    code: str,
    detail: str,
    errors: list[ProblemError] | None = None,
) -> Problem:
    problem: Problem = {
        "type": PROBLEM_TYPE_BLANK,
        "title": HTTPStatus(status).phrase,
        "status": status,
        "detail": detail,
        "code": code,
        "request_id": get_request_id(),
    }
    if errors:
        problem["errors"] = errors
    return problem


def problem_response(
    *,
    status: int,
    code: str,
    detail: str,
    errors: list[ProblemError] | None = None,
    headers: dict[str, Any] | None = None,
) -> JsonResponse:
    """Problem Details as a plain Django response (for non-DRF error paths)."""
    return JsonResponse(
        build_problem(status=status, code=code, detail=detail, errors=errors),
        status=status,
        content_type=PROBLEM_CONTENT_TYPE,
        headers=headers,
    )
