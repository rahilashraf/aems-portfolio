# ADR-0007: API error format (RFC 9457 Problem Details)

- **Status:** Accepted; refined by [ADR-0009](0009-api-error-response-conventions.md)
- **Date:** 2026-11-21

## Context

Clients need consistent, machine-readable errors. DRF's default error bodies vary by exception type.

## Decision

All error responses use RFC 9457 `application/problem+json` with `type`, `title`, `status`,
`detail`, a stable application `code`, optional `errors` (field-level), and `request_id`.
A custom DRF exception handler maps DRF, Django, and domain exceptions. Unhandled exceptions
return a generic 500 containing only the `request_id`; details are logged server-side.

## Alternatives considered

- *DRF default format*: inconsistent shapes across exception types.
- *Custom envelope*: reinvents an existing IETF standard.

## Consequences

- Frontend can branch on `code` without parsing human-readable messages.
- Error responses are documented in the OpenAPI schema.
