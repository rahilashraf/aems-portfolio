# ADR-0006: Audit logging

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

Institutions need a trustworthy record of security-relevant actions (authentication, membership,
roles, invitations). Records must be consistent with the data they describe, tamper-resistant,
and must never leak secrets.

## Decision

- Semantic events recorded **explicitly from services** (`audit.record(...)`) rather than through
  model signals.
- **Atomicity**: events for mutations are written inside the same transaction as the mutation.
- **Security events** (failed login, rate limiting, invalid tokens, refresh replay) are written by
  `audit.record_security_event(...)` in their own transaction, independent of any business
  transaction that rolled back; `ATOMIC_REQUESTS` is not used. Each event carries `outcome`
  (`success`/`failure`).
- **Append-only**: enforced in the model/queryset layer and by a PostgreSQL trigger rejecting
  `UPDATE`/`DELETE`; runtime role granted only `INSERT`/`SELECT` on the table.
- **Redaction**: allowlisted fields only in `changes`; known secret types never recorded; a test
  scans all events produced during the test suite for secret values.

## Alternatives considered

- *Signals*: miss bulk operations, lack request context and business meaning.
- *django-auditlog / django-simple-history*: row-diff oriented; we need semantic, cross-model events.
- *Hash-chained tamper evidence*: valuable, deferred; can be added without changing the event schema.

## Consequences

- Every new sensitive service must call the audit service; reviewed in PRs and covered by tests.
- Retention, archival, and export policies are future work.
