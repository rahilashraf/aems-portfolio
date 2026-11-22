# ADR-0010: Request correlation and structured logging

- **Status:** Accepted
- **Date:** 2026-11-22

## Context

Operating a multi-tenant system requires correlating every log line and error response with the
request that produced it, using machine-parseable logs, without leaking credentials or personal
data into logs.

## Decision

- **Request IDs.** `RequestContextMiddleware` (first in `MIDDLEWARE`) accepts a client-supplied
  `X-Request-ID` only if it matches `^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$` (8–128 safe characters,
  so it cannot be used for header or log injection). Otherwise it generates a UUIDv4. The ID is
  returned in the `X-Request-ID` response header and included in Problem Details bodies.
- **Context propagation** uses `contextvars` (`structlog.contextvars`), which are isolated per
  thread and per asyncio task. The context is cleared at the start of each request, immediately
  if an exception propagates through the middleware, and otherwise by a `request_finished`
  receiver once the response is closed. The later clear means Django's own `django.request` log
  lines, which are written after the middleware chain returns, still carry the request ID. The
  context cannot leak across requests.
  Batch 3 will bind `user_id` and Batch 4 `organization_id` through `bind_request_context()`.
- **structlog** with standard-library integration (`ProcessorFormatter`), so Django and
  third-party logs share one pipeline. JSON (one object per line, sorted keys, UTC ISO timestamps)
  is the default and production format; local development uses readable console output
  (`DJANGO_LOG_FORMAT`).
- **Access log.** One `request.completed` event per request with method, the **matched route
  pattern** (never the raw path, and never the query string), status, duration and `REMOTE_ADDR`.
  Health probes are logged at DEBUG.
- **Sensitive data** (`apps/core/sanitization.py`).
  - A redaction processor replaces values under sensitive keys (password, token, secret,
    authorization, cookie, session, csrf, api key, credential, signature, private key, dsn),
    recursively and with bounds (AEMS-008):
    - beyond depth 8 values become `[TRUNCATED]` and are never returned raw;
    - containers are capped at 100 entries;
    - at most 2,000 nodes are visited per value;
    - circular references become `[CIRCULAR]`.
  - Free text (log messages and rendered tracebacks) is sanitized. This covers URL credentials,
    sensitive `key=value` pairs, Bearer/Basic credentials, JWT-shaped tokens, URL query strings,
    PostgreSQL `Key (...)=(...)` details and quoted literals on SQL `LINE n:` lines. Text is
    capped at 8 KiB.
  - Tracebacks are rendered without local variables.
  - A logging filter redacts the raw path that Django's `django.request` logger includes in
    4xx/5xx messages, and the request line written by the development server.
  - SQL logging (`django.db.backends`) is pinned to WARNING.
  - gunicorn's access log is disabled in the production image, because it prints query strings.
  - Request headers, cookies and bodies are never logged.
- **Client IP.** Only `REMOTE_ADDR` is used. `X-Forwarded-For` is not trusted until a
  trusted-proxy configuration is designed and approved.
- **django-structlog was not adopted.** Its client-IP resolution reads forwarded headers by
  default, and it logs request paths. A small first-party middleware keeps these policies explicit
  and tested.

## Consequences

- Redaction is a safety net; code must still avoid logging secrets.
- Unmatched requests (404s) log `route: null`, which trades some debuggability for not logging
  attacker- or user-supplied paths.
- gunicorn's own error log is plain text (not JSON); acceptable until deployment work.
