# ADR-0009: API error response conventions (refines ADR-0007)

- **Status:** Accepted
- **Date:** 2026-11-22
- **Refines:** [ADR-0007](0007-api-error-format.md)

## Context

ADR-0007 chose RFC 9457 Problem Details. Implementing it (Batch 2) required concrete decisions on
the `type` URI, how validation errors are structured, which exceptions may expose their message,
and how errors raised outside DRF are handled. ADR-0007's example used an `https://aems.dev/...`
type URI, which AEMS does not own or serve.

## Decision

1. **`type` is `about:blank`** for all errors, with `title` set to the HTTP status phrase, as RFC 9457
   prescribes for `about:blank`. AEMS-specific semantics are carried by the stable `code`
   extension member (for example `validation_error`, `invalid_query_parameters`, `conflict`,
   `page_not_found`). Dereferenceable problem-type URIs can be introduced later, once the project
   has a stable documentation host; doing so will not change `code`.
2. **Members:** `type`, `title`, `status`, `detail`, `code`, `request_id` (also in the `X-Request-ID`
   header) and, for validation failures, `errors`.
3. **`errors` entries:** `{detail, code, pointer}` for request-body errors, where `pointer` is an
   RFC 6901 JSON Pointer in URI-fragment form (`#/items/1/sku`, `#` for non-field errors); and
   `{detail, code, parameter}` for query-parameter errors (pagination, filtering, ordering).
4. **Client-safe messages only (AEMS-009).**
   - **Domain errors** that need a specific client message subclass `DomainError`, for example
     `ConflictError` and `PageNotFoundError`. Their messages must be static and must contain no
     secrets, credentials, internal identifiers, SQL, file paths or exception text. Only
     `DomainError` messages are passed through, and they are still sanitized and capped at 300
     characters as a safety net.
   - **All other exceptions** get a fixed, generic message chosen by type, whatever text they
     were raised with. This covers DRF built-ins (`ParseError`, `AuthenticationFailed`,
     `PermissionDenied`, `NotFound`, `Throttled` and others), Django's `Http404` and
     `PermissionDenied`, and unknown `APIException` subclasses. Parser messages, for example, are
     never echoed.
   - **Validation messages** are field-level and meant for clients, but they must not echo
     submitted values. As a safety net:
     - errors on sensitive fields (password, token, secret, key and similar names anywhere in the
       pointer path) get a generic message;
     - every message is text-sanitized and capped;
     - error codes must match `^[a-z][a-z0-9_]{0,63}$`;
     - at most 100 errors are reported.
   - **Unhandled exceptions** return a generic `500 internal_error`. The traceback is logged
     server-side with the request ID, without local variables and after text sanitization
     (ADR-0010).
5. **Headers are preserved:** DRF's default handler still runs first, so `WWW-Authenticate`
   (401), `Retry-After` (429) and `Allow` (405) are retained.
6. **Errors outside DRF** (unknown URLs, disallowed hosts, CSRF failures, crashes in plain Django
   views) use `handler400/403/404/500` and `CSRF_FAILURE_VIEW`, which return the same format.
   With `DEBUG=True` (local only) Django's debug pages take precedence.
7. **Fail closed on misconfiguration.** Views that violate API conventions (for example a missing
   ordering allowlist) raise `ImproperlyConfigured`, which surfaces as a generic 500 and a logged
   error rather than an unrestricted response.

## Consequences

- Clients branch on `code` and `status`, never on `detail` text.
- The OpenAPI schema documents the Problem Details shape on every operation (post-processing hook).
- The 403-versus-401 distinction becomes meaningful once authentication exists (Batch 3). Until
  then the deny-by-default permission yields 403.
