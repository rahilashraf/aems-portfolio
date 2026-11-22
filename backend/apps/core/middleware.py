"""Request correlation and access logging middleware."""

import time
from collections.abc import Callable

import structlog
from django.http import HttpRequest, HttpResponseBase

from .request_context import (
    REQUEST_ID_HEADER,
    REQUEST_ID_META_KEY,
    bind_request_context,
    clear_request_context,
    resolve_request_id,
)

access_logger = structlog.get_logger("aems.request")

_QUIET_ROUTE_PREFIXES = ("health/",)


class RequestContextMiddleware:
    """Assign a request ID, bind it to the log context, and log request completion.

    Must be the first entry in ``MIDDLEWARE`` so every response (including redirects and errors
    produced by later middleware) carries the ``X-Request-ID`` header.

    Logged fields are deliberately minimal: method, the *matched route pattern* (never the raw
    path, which may contain tokens; never the query string), status, duration and the socket peer
    address (``REMOTE_ADDR``). Forwarded-for headers are not trusted here; client-IP resolution
    behind a proxy requires an explicit trusted-proxy configuration (future work).

    Context lifecycle: cleared at the start of every request; on the normal path it stays bound
    until Django's ``request_finished`` signal (response closed) clears it, so Django's own
    ``django.request`` log lines, which are written after the middleware chain returns, still
    carry the request ID. If anything raises through this middleware the context is cleared
    immediately.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponseBase]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponseBase:
        clear_request_context()
        request_id = resolve_request_id(request.META.get(REQUEST_ID_META_KEY))
        request.request_id = request_id  # type: ignore[attr-defined]
        bind_request_context(request_id=request_id)
        started = time.perf_counter()
        try:
            response = self.get_response(request)
            response[REQUEST_ID_HEADER] = request_id
            self._log_completion(request, response, started)
        except BaseException:
            clear_request_context()
            raise
        return response

    @staticmethod
    def _log_completion(request: HttpRequest, response: HttpResponseBase, started: float) -> None:
        match = getattr(request, "resolver_match", None)
        route = match.route if match is not None else None
        log = (
            access_logger.debug
            if route and route.startswith(_QUIET_ROUTE_PREFIXES)
            else access_logger.info
        )
        log(
            "request.completed",
            method=request.method,
            route=route,
            status_code=response.status_code,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            client_ip=request.META.get("REMOTE_ADDR"),
        )
