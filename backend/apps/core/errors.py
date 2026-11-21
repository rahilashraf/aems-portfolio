"""Django-level error views (``handler400/403/404/500`` and CSRF failures).

These cover errors raised outside DRF views: unknown URLs, disallowed hosts, CSRF failures,
and unhandled exceptions in plain Django views. All return RFC 9457 Problem Details with fixed,
client-safe messages; exception details are never included in responses.

Django uses these handlers only when ``DEBUG`` is False; in local development Django's debug
pages are shown instead.
"""

import structlog
from django.http import HttpRequest, JsonResponse

from .problems import problem_response

logger = structlog.get_logger(__name__)


def bad_request(request: HttpRequest, exception: Exception | None = None) -> JsonResponse:
    return problem_response(
        status=400, code="bad_request", detail="The request could not be processed."
    )


def permission_denied(request: HttpRequest, exception: Exception | None = None) -> JsonResponse:
    return problem_response(
        status=403,
        code="permission_denied",
        detail="You do not have permission to perform this action.",
    )


def page_not_found(request: HttpRequest, exception: Exception | None = None) -> JsonResponse:
    return problem_response(
        status=404, code="not_found", detail="The requested resource was not found."
    )


def server_error(request: HttpRequest) -> JsonResponse:
    # Django has already logged the exception (``django.request`` logger) with the request ID
    # bound in the log context; nothing about it is exposed to the client.
    return problem_response(
        status=500, code="internal_error", detail="An unexpected error occurred."
    )


def csrf_failure(request: HttpRequest, reason: str = "") -> JsonResponse:
    logger.warning("security.csrf_failure", reason=reason)
    return problem_response(status=403, code="csrf_failed", detail="CSRF verification failed.")
