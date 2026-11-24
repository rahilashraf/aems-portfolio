# ADR-0019: Phase 1 security hardening and review

- **Status:** Accepted (pending review of Batch 8)
- **Date:** 2026-11-24

## Context

Batch 8 closes Phase 1. Its job was a structured review of everything built in Batches 1-7, not
new features. The review covered:

- authentication;
- tenancy and RBAC;
- invitations;
- the email outboxes;
- audit;
- database privileges;
- production settings;
- input handling.

For each area the review identified the intended security boundary, read the code and the existing
tests, and wrote adversarial tests against real PostgreSQL. Three kinds of attempt were used:

- HTTP requests;
- raw SQL as the restricted runtime role;
- synchronized threads.

An independent read-only review of the outboxes, the audit API, the admin and the serializers ran
in parallel. Every reported issue was reproduced, or checked against the code, before it was
accepted.

Ten issues were confirmed and fixed (AEMS-019 to AEMS-028). This ADR records them and the design
clarifications they introduce. The tests live in `backend/tests/security/`; see
[`SECURITY.md`](../../SECURITY.md) for the operational model and
[`docs/phase-1-final-report.md`](../phase-1-final-report.md) for the assessment.

## Decision

### Verified findings and their fixes

| ID | Severity | Finding | Fix |
|---|---|---|---|
| AEMS-021 | High | A non-superuser staff account holding `accounts.change_user` could set the password, email address or active state of **superusers and other staff** in the Django admin. Reproduced: an operator reset a superuser's password and changed its email address. Users and sessions could also be deleted in the admin, bypassing the audited deactivation and revocation services. | Only superusers may change, or set the password of, a staff or superuser account. The admin never deletes accounts or sessions. |
| AEMS-027 | Medium | **Deadlocks** between ownership operations. Tenant mutations hold the organization lock and insert rows referencing the acting user (for example the audit row's `actor_id`). Each such insert takes `FOR KEY SHARE` on the user row. Deactivation, password changes, profile updates and invitation acceptance lock that user row `FOR UPDATE` and then wait for the organization. The two lock modes conflict, which turned the documented user → organization order into a cycle. Reproduced: 43 deadlock aborts in 40 rounds of six concurrent operations. PostgreSQL aborted one transaction each time, so the Owner invariant held, but the client received a 500. | Serialization locks on users and organizations use `SELECT … FOR NO KEY UPDATE` (`select_for_update(no_key=True)`). They still exclude each other and every update of those rows, but not foreign-key checks; primary keys are never updated. After the fix: 0 aborts in 40 rounds. A meta-test fails if a user or organization lock without `no_key=True` is added. |
| AEMS-023 | Medium | Production accepted the console, file, in-memory and dummy email backends; `EMAIL_URL` defaulted to the console. One-time invitation and reset links would have been printed to job logs or files, and the outboxes would have recorded them as "delivered". Unencrypted SMTP was also accepted. | Production refuses any backend other than SMTP. Plain SMTP requires `AEMS_EMAIL_ALLOW_UNENCRYPTED_SMTP=true`, meant for an isolated test network; the CI container uses it for Mailpit. |
| AEMS-024 | Medium | `max_attempts` was enforced only when sending raised. A delivery run killed after claiming a row recorded nothing, so the row was reclaimed after every lease without limit. For invitations, each reclaim rotated the token and sent another email until the invitation expired. | A row claimed more than `max_attempts` times is failed with the permanent category `abandoned`, without sending or issuing a token. |
| AEMS-025 | Medium | Every rate-limited request and every failed CSRF check on the public cookie endpoints wrote a durable audit row. Unauthenticated clients could therefore grow the append-only table without bound. | The first refusal per limit scope, key and window is recorded durably; later ones go to the structured log only. Failed CSRF checks are recorded durably up to 20 per IP per 5 minutes, then logged only. Responses are unchanged. |
| AEMS-019 | Low | Oversized JSON bodies (Django's `RequestDataTooBig`) and deeply nested JSON (`RecursionError`) produced unhandled 500s with error-level logs. Reproduced through Django's WSGI handler. | `413 request_too_large` via the Problem Details handler. `BoundedJSONParser` rejects bodies nested more than 32 levels deep, and parser recursion errors, with `400 parse_error`. |
| AEMS-020 | Low | A client could decode and re-encode the audit cursor with an arbitrary position. Invalid or naive timestamps reached the query: a 500 under strict warnings, or a silently reinterpreted position otherwise. The tenant filter still applied, so no data leaked. | Positions must be timezone-aware timestamps; anything else is the documented 404. |
| AEMS-022 | Low | Email changes made in the admin, the only way to change an address (ADR-0018), were not audited. | `email` is an audited account field and an allowlisted change field. |
| AEMS-026 | Low | Production accepted plain-HTTP and wildcard `CSRF_TRUSTED_ORIGINS`. | Production accepts explicit `https://` origins only. |
| AEMS-028 | Low | Owners were granted every registry-active code even when the database marked the code deprecated, contrary to the engine's documented contract. Codes diverge only through manual database edits. | The Owner set excludes database-deprecated codes. |

### Reviewed and confirmed (no change)

- **JWT validation.** PyJWT enforces a single algorithm (HS256), the signature, `exp`, and `iat`
  not in the future (leeway 0), plus `iss`/`aud` when configured. The project adds the required
  claims, the token type, UUID-shaped identifiers and the per-request session/user check.
  `alg=none`, other HMAC algorithms, RSA/EC confusion headers, a tampered payload with the
  original signature, a cross-user `sid` and a refresh token presented as an access token are all
  rejected (`test_authentication_attacks.py`). An application-level `iat` check was tried and
  removed as redundant.
- **Tokens in logs.** Django's own 4xx/5xx request log lines already redact the path (ADR-0010).
  Invitation and reset tokens appear in no logs, responses, audit rows, outbox rows or admin
  pages (`test_invitation_attacks.py`, `test_password_reset_attacks.py`).
- **Forwarded headers.** `X-Forwarded-For` and `X-Real-IP` are ignored unless
  `DJANGO_TRUSTED_PROXY_COUNT` is set. Spoofing cannot evade the limits
  (`test_rate_limiting.py`).
- **Concurrent limiter.** One statement per hit: 20 simultaneous attempts against a limit of 5
  admit exactly 5.

### Clarifications

1. **Lock modes.** "Locking" a user or organization row in the global lock order (ADR-0017,
   ADR-0018) means `FOR NO KEY UPDATE`. Membership, role, invitation and outbox locks are
   unchanged; they are always taken after the organization lock.
2. **Audit volume.** Refusals are security signals, not records of state changes. One durable
   record per window, plus the log stream, preserves detection without letting anonymous clients
   control the size of the audit table.
3. **Admin authority.** Platform staff manage ordinary accounts. Privileged accounts (staff or
   superuser) are managed by superusers only, and nothing is deleted through the admin.
4. **Request bodies.** API bodies are JSON only and at most 2.5 MiB
   (`DATA_UPLOAD_MAX_MEMORY_SIZE`), with nesting of at most 32 levels. Oversized bodies get 413;
   malformed or excessive structure gets 400.
5. **Production email.** SMTP only, encrypted unless explicitly opted out on a test network.

### Security test suites

`backend/tests/security/` is the cross-cutting suite named in the Phase 1 plan §10:

| Module | Covers |
|---|---|
| `test_route_policy.py` | Every route classified (public, token, authenticated, tenant, platform, docs, health); allowlist equality; live anonymous, garbage-credential and unprivileged-platform checks; default deny; catalog agreement |
| `test_tenant_isolation_matrix.py` | Every caller category against every tenant endpoint with full-table snapshots; foreign nested ids; cross-tenant body ids; closed and unknown organizations |
| `test_authentication_attacks.py` | JWT forgery and malformed claims; session lifecycle; refresh replay and concurrency; cookie attributes; CSRF; CORS; content types |
| `test_password_reset_attacks.py` | Enumeration (status, body, headers, cookies, mail timing); token tampering, expiry, reuse and concurrent use; secret leakage |
| `test_invitation_attacks.py` | Token formats, guesses and brute force; uniform invalid responses; identity and privilege attacks; delivery races; leakage |
| `test_rbac_owner_security.py` | Escalation over the API and services; deprecated codes; a six-way ownership stress test (AEMS-027) |
| `test_audit_integrity.py` | Required events; audit-failure rollback; no false success; body injection; secret scan; tenant and platform audit queries |
| `test_database_safeguards.py` | Raw SQL as the runtime role against every trigger, composite key and privilege; reverse-and-reapply of the migrations |
| `test_rate_limiting.py` | Concurrency at the boundary; window boundaries; client-IP resolution; spoofing; every public entry point |
| `test_input_validation.py` | Body size and depth (AEMS-019); content types; field validation; query tampering (AEMS-020); error disclosure |
| `test_production_settings_hardening.py` | Settings snapshot; email (AEMS-023); CSRF origins (AEMS-026); `check --deploy` failures |
| `test_admin_security.py` | AEMS-021, AEMS-022 |
| `test_outbox_and_event_flooding.py` | AEMS-024, AEMS-025 |

## Alternatives considered

- **Separate, non-durable rate-limit counters for audit throttling.** Rejected: the existing atomic
  limiter already provides per-window counts, and the first-denial flag needs no new table.
- **Lock ordering by removing foreign keys from the audit table.** Rejected: the foreign keys are
  part of audit integrity. Changing the lock mode is the standard PostgreSQL remedy.
- **Application-level `iat` validation.** Rejected as redundant with PyJWT's own check.
- **Blocking unencrypted SMTP outright.** Rejected: the CI end-to-end test needs Mailpit. The
  opt-in is explicit, documented, and refused for non-SMTP backends.

## Consequences

- Phase 1 has no known unresolved security defect in the reviewed scope. The residual risks and
  deferred capabilities are listed in `SECURITY.md` and the final report. They include RLS
  (Phase 2), retention, database-level tenant immutability for unreferenced rows, and
  authenticated audit growth.
- Operators must configure TLS SMTP in production and keep both delivery commands scheduled.
- Staff accounts can no longer manage other staff accounts; only superusers can.
