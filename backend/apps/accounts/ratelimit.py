"""Atomic, PostgreSQL-backed authentication rate limiting (ADR-0004 §abuse protection).

- Counters live in ``AuthRateLimit`` keyed by ``(scope, key_digest, window_start)``. Each attempt is
  one ``INSERT ... ON CONFLICT DO UPDATE SET count = count + 1 RETURNING count`` statement, which is
  atomic under concurrency (no lost updates, unlike cache read-modify-write throttles).
- Keys are HMAC-SHA256 digests of the identifier (IP, normalized email, user id), so raw emails and
  IP addresses are never stored.
- ``AuthBackoff`` tracks consecutive login failures per account digest. From the
  ``threshold``-th failure the account digest is locked for ``base * 2^(n - threshold)`` seconds,
  capped at ``cap``. The lock applies to any submitted email (existing or not), so it reveals
  nothing about account existence; it is temporary, so it cannot become a permanent denial of
  service.
"""

import math
from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from django.conf import settings
from django.db import connection
from django.utils import timezone
from django.utils.crypto import salted_hmac

from .models import AuthBackoff, AuthRateLimit


@dataclass(frozen=True)
class Limit:
    max_attempts: int
    window_seconds: int


# Literal SQL (no string interpolation). Table names are asserted against the models in tests.
RATE_LIMIT_TABLE = "accounts_authratelimit"
BACKOFF_TABLE = "accounts_authbackoff"
_INCREMENT_SQL = """
    INSERT INTO accounts_authratelimit (scope, key_digest, window_start, count, expires_at)
    VALUES (%s, %s, %s, 1, %s)
    ON CONFLICT (scope, key_digest, window_start)
    DO UPDATE SET count = accounts_authratelimit.count + 1
    RETURNING count
"""
_REGISTER_FAILURE_SQL = """
    INSERT INTO accounts_authbackoff (key_digest, failures, locked_until, expires_at)
    VALUES (%s, 1, NULL, %s)
    ON CONFLICT (key_digest) DO UPDATE SET
        failures = accounts_authbackoff.failures + 1,
        expires_at = EXCLUDED.expires_at
    RETURNING failures
"""
_LOCK_SQL = "UPDATE accounts_authbackoff SET locked_until = %s WHERE key_digest = %s"


def _limits() -> dict[str, Limit]:
    configured = getattr(settings, "AUTH_RATE_LIMITS", {})
    return {scope: Limit(*values) for scope, values in configured.items()}


def digest(kind: str, value: str) -> str:
    """HMAC-SHA256 of an identifier; ``kind`` separates namespaces (ip, email, user...)."""
    return salted_hmac("aems.accounts.ratelimit", f"{kind}:{value}", algorithm="sha256").hexdigest()


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    count: int
    retry_after: int
    # True only for the first refused attempt of a window. Callers record a durable audit event
    # for that one and log the rest, so refused floods cannot grow the append-only audit table
    # without bound (review finding AEMS-025).
    first_denial: bool = False


def hit(scope: str, key_digest: str, now: datetime | None = None) -> RateLimitResult:
    """Count one attempt in ``scope`` and report whether it is within the limit."""
    limit = _limits()[scope]
    now = now or timezone.now()
    window = limit.window_seconds
    window_start_ts = math.floor(now.timestamp() / window) * window
    window_start = datetime.fromtimestamp(window_start_ts, tz=now.tzinfo)
    window_end = window_start + timedelta(seconds=window)
    with connection.cursor() as cursor:
        cursor.execute(_INCREMENT_SQL, [scope, key_digest, window_start, window_end])
        row = cursor.fetchone()
    count = int(row[0]) if row else 1
    retry_after = max(1, math.ceil((window_end - now).total_seconds()))
    return RateLimitResult(
        allowed=count <= limit.max_attempts,
        count=count,
        retry_after=retry_after,
        first_denial=count == limit.max_attempts + 1,
    )


def check_all(hits: list[tuple[str, str]], now: datetime | None = None) -> RateLimitResult | None:
    """Count an attempt in several scopes; return the first exceeded result (largest retry)."""
    now = now or timezone.now()
    exceeded = [r for r in (hit(scope, key, now) for scope, key in hits) if not r.allowed]
    if not exceeded:
        return None
    longest = max(exceeded, key=lambda r: r.retry_after)
    return replace(longest, first_denial=any(r.first_denial for r in exceeded))


# --------------------------------------------------------------------------- account backoff
def _backoff_settings() -> tuple[int, int, int]:
    cfg = getattr(settings, "AUTH_LOGIN_BACKOFF", {})
    return (
        int(cfg.get("threshold", 5)),
        int(cfg.get("base_seconds", 30)),
        int(cfg.get("cap_seconds", 900)),
    )


def backoff_remaining(key_digest: str, now: datetime | None = None) -> int:
    """Seconds until the account digest may attempt again (0 if not locked)."""
    now = now or timezone.now()
    locked_until = (
        AuthBackoff.objects.filter(key_digest=key_digest, locked_until__gt=now)
        .values_list("locked_until", flat=True)
        .first()
    )
    if locked_until is None:
        return 0
    return max(1, math.ceil(float((locked_until - now).total_seconds())))


def register_failure(key_digest: str, now: datetime | None = None) -> int:
    """Atomically record a failure; return the resulting lock duration in seconds (0 if none)."""
    threshold, base, cap = _backoff_settings()
    now = now or timezone.now()
    with connection.cursor() as cursor:
        cursor.execute(_REGISTER_FAILURE_SQL, [key_digest, now + timedelta(days=1)])
        row = cursor.fetchone()
        failures = int(row[0]) if row else 1
        if failures < threshold:
            return 0
        seconds = int(min(cap, base * 2 ** (failures - threshold)))
        cursor.execute(_LOCK_SQL, [now + timedelta(seconds=seconds), key_digest])
    return seconds


def reset_failures(key_digest: str) -> None:
    AuthBackoff.objects.filter(key_digest=key_digest).delete()


def purge_expired(now: datetime | None = None) -> tuple[int, int]:
    now = now or timezone.now()
    counters, _ = AuthRateLimit.objects.filter(expires_at__lt=now).delete()
    backoffs, _ = AuthBackoff.objects.filter(expires_at__lt=now).delete()
    return counters, backoffs
