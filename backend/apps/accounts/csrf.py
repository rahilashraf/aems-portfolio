"""Explicit Django CSRF enforcement for cookie-authenticated endpoints (ADR-0004).

DRF views are CSRF-exempt by default; bearer-authenticated requests do not need CSRF protection
because browsers never attach the Authorization header automatically. The refresh cookie *is*
attached automatically, so every endpoint that acts on it calls :func:`enforce_csrf`, which runs
Django's ``CsrfViewMiddleware`` checks: the ``X-CSRFToken`` header must match the ``csrftoken``
cookie, and the ``Origin`` (or, over HTTPS, ``Referer``) must be the request's own origin or listed
in ``CSRF_TRUSTED_ORIGINS``.
"""

from typing import Any

from django.http import HttpRequest, HttpResponse
from rest_framework.authentication import CSRFCheck

from apps.core.api.exceptions import DomainError
from apps.core.security_events import record_security_event


class CsrfFailedError(DomainError):
    status_code = 403
    default_detail = "CSRF verification failed."
    default_code = "csrf_failed"


def _noop(request: HttpRequest) -> HttpResponse:  # pragma: no cover - never called
    return HttpResponse()


def enforce_csrf(request: Any) -> None:
    django_request: HttpRequest = getattr(request, "_request", request)
    check = CSRFCheck(_noop)
    check.process_request(django_request)
    reason = check.process_view(django_request, _noop, (), {})
    if reason:
        record_security_event("auth.csrf.failed", outcome="failure", reason=str(reason))
        raise CsrfFailedError()
