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

from apps.audit import services as audit
from apps.core.api.exceptions import DomainError
from apps.core.net import client_ip
from apps.core.security_events import log_security_event

from . import ratelimit


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
        _record_failure(django_request, str(reason))
        raise CsrfFailedError()


def _record_failure(request: HttpRequest, reason: str) -> None:
    """Durable ``auth.csrf.failed`` within the per-IP budget, a log line beyond it (AEMS-025).

    The cookie endpoints are public, so without a budget anyone could append audit rows at will.
    The response (403) is the same either way.
    """
    ip = client_ip(request)
    within_budget = ratelimit.hit("csrf_failure_ip", ratelimit.digest("ip", ip or "unknown"))
    if within_budget.allowed:
        audit.record_security_event("auth.csrf.failed", client_ip=ip, metadata={"reason": reason})
    else:
        log_security_event("auth.csrf.failed", outcome="failure", client_ip=ip, repeated=True)
