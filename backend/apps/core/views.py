"""Operational health endpoints.

- ``/health/live/``  — liveness: the process is up and serving requests. No dependencies checked,
  so an unavailable database never causes an orchestrator to restart healthy processes.
- ``/health/ready/`` — readiness: required dependencies (PostgreSQL) are reachable.

Responses never include exception details, hostnames, or versions.
"""

import logging

from django.db import DatabaseError, connections
from django.http import HttpRequest, JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_safe

logger = logging.getLogger(__name__)


def _database_ok(alias: str = "default") -> bool:
    try:
        with connections[alias].cursor() as cursor:
            cursor.execute("SELECT 1")
            row = cursor.fetchone()
    except DatabaseError:
        logger.exception("Readiness check failed: database %r unreachable", alias)
        return False
    return bool(row == (1,))


@never_cache
@require_safe
def liveness(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"status": "ok"})


@never_cache
@require_safe
def readiness(request: HttpRequest) -> JsonResponse:
    database_ok = _database_ok()
    payload = {
        "status": "ok" if database_ok else "unavailable",
        "checks": {"database": "ok" if database_ok else "unavailable"},
    }
    return JsonResponse(payload, status=200 if database_ok else 503)
