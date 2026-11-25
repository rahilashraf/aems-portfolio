# Security

AEMS (Assessment & Examination Management System) is a multi-tenant backend built as a
portfolio project. This document describes how to report vulnerabilities, the security model
implemented in Phase 1, the configuration a deployment must provide, how to operate the
security-relevant background commands, and the known limitations.

> **Status.** Phase 1 (backend foundation) has been implemented and reviewed in eight batches.
> AEMS has **not** been deployed, penetration-tested by a third party or certified against any
> standard. Passing the automated checks described here is evidence of the implemented controls,
> not a production certification.

## Supported versions

| Version | Supported |
|---|---|
| `main` (Phase 1 backend) | Yes: security fixes are made on `main` |
| Any other branch or fork | No |

There are no tagged releases yet.

## Reporting a vulnerability

Please **do not open a public issue, pull request or discussion** for a suspected vulnerability.

- **Preferred:** use GitHub's private vulnerability reporting on this repository (**Security** tab →
  **Report a vulnerability**). It is available only if the repository owner has enabled it in
  *Settings → Code security*. Enabling it is an owner configuration step that this repository
  cannot verify for you.
- **Otherwise:** contact the repository owner, GitHub account `rahilashraf`, privately through
  GitHub, and ask for a private channel before sharing details.

No dedicated security mailbox, bug bounty or response-time commitment exists. Include the affected
commit, the endpoint or component, reproduction steps and the impact you observed. Do not access
data that is not yours, do not degrade availability, and do not test against any deployment
without its operator's written permission.

Coordinated disclosure: please allow the owner reasonable time to investigate and fix before
publishing. Fixed vulnerabilities are recorded as review findings (`AEMS-NNN`) in the ADRs.

## Security architecture

Phase 1 is a Django 5.2 LTS / Django REST Framework / PostgreSQL backend. Every boundary is
enforced in the backend and, where possible, again in the database.

| Area | Control | Reference |
|---|---|---|
| Authentication | Short-lived JWT access tokens (10 min, HS256, dedicated key), each checked against a server-side session on **every** request; rotating refresh token in an `HttpOnly; Secure; SameSite=Strict` cookie; replay revokes the whole session | ADR-0004, ADR-0013 |
| Tenant isolation | Shared schema with `organization_id` on every tenant row; the organization comes only from the URL; one query resolves an active membership in an active organization; everything else is the same 404 | ADR-0003, ADR-0015 |
| Authorization | Per-action declarations with default deny; organization RBAC with fresh permission checks inside locked transactions; platform authority is separate and never implies tenant access | ADR-0012, ADR-0017 |
| Ownership | Every active organization keeps at least one active Owner, enforced under row locks against every reducing operation, including global deactivation | ADR-0005, ADR-0017 |
| Invitations | 256-bit single-use tokens, stored only as SHA-256 digests, issued when the email is sent, expiring after 7 days; acceptance revalidates identity and the inviter's authority under locks | ADR-0018 |
| Audit | Mutations and their audit records commit atomically; allowlisted, redacted metadata; append-only by trigger and by privileges | ADR-0006, ADR-0016 |
| Database | Separate owner (migrations) and runtime (application) roles; composite foreign keys and triggers protect tenancy, the permission catalog, invitations and audit rows | ADR-0016, ADR-0017, ADR-0018 |
| Abuse | Atomic PostgreSQL rate limiter and per-account backoff; generic responses for login, password reset and invitation tokens | ADR-0004, ADR-0013 |
| API | JSON only; 2.5 MiB body cap (413); nesting limit (400); RFC 9457 errors with stable codes and request ids; no internal details | ADR-0007, ADR-0009, ADR-0019 |
| Hardening review | Batch 8 findings AEMS-019 to AEMS-028 and the cross-cutting security suites | ADR-0019 |

### Authentication and token handling

- Access tokens are returned in the response body and must be kept **in memory only** by clients:
  never in `localStorage` or `sessionStorage`.
- Refresh tokens exist only in the `aems_refresh` cookie (`Path=/api/v1/auth/`). Refresh and
  logout with the cookie require a matching `X-CSRFToken` header and an allowed `Origin`.
- Logout, revoking a session, revoking other sessions, password change, password reset and
  deactivation take effect **immediately** for every token of the affected sessions.
- Login failures, unknown accounts and inactive accounts are indistinguishable. Accounts back off
  exponentially after repeated failures, whether or not the account exists.
- Password-reset links carry the token in the URL fragment. Reset tokens are single-use and
  expire after `DJANGO_PASSWORD_RESET_TIMEOUT` seconds. The request endpoint always answers 202
  and never sends mail itself.
- MFA, SSO and self-service signup are out of scope for Phase 1.

### Organization and tenant isolation

- Tenant routes live under `/api/v1/organizations/{org_id}/`. Every route is classified, and a
  CI meta-test fails if a new route is unclassified (`backend/tests/security/test_route_policy.py`).
- Non-members, suspended members, inactive accounts, provisioning or suspended organizations and
  unknown ids all receive the same 404. Platform staff and superusers have no tenant access
  through the tenant API.
- References to other tenants' objects, in URLs or in request bodies, behave exactly like ids
  that do not exist. Composite foreign keys make cross-tenant role assignments impossible even with
  raw SQL.

### RBAC and Owner protection

- Eight catalog permissions. Owner (all permissions), Admin and Member are seeded per organization,
  and custom roles are supported.
- No self-promotion, and no self-modification of one's own membership. Granting anything requires
  holding it; only Owners grant or remove Owner.
- Ownership-reducing operations lock the organization and recount active Owners. The last active
  Owner cannot be removed, suspended, demoted or deactivated (`409 last_owner`).
- Lock order: user → organizations (ascending id) → memberships (ascending id) → roles. User and
  organization rows are locked `FOR NO KEY UPDATE` (AEMS-027).

### Audit integrity

- Mutations write their audit record in the same transaction: if the record cannot be written,
  the change rolls back. Independent security events (failed logins, rate limits, CSRF failures,
  rejected tokens) are written in their own transaction.
- Audit rows cannot be updated or deleted: a trigger blocks it for every role, and the runtime role
  holds only `SELECT` and `INSERT` on the table.
- Metadata keys are allowlisted and typed; passwords, hashes, tokens (raw or hashed), cookies and
  request bodies never reach the table.
- Repeated refusals are recorded durably once per rate-limit window and logged thereafter
  (AEMS-025). This applies to the API and to the Django admin sign-in.

### Database-role separation

| Role | Used by | Privileges |
|---|---|---|
| Owner (`aems_owner`) | `migrate`, the test suite | Owns every table, the triggers and the migrations |
| Runtime (`aems_app`) | The application | Data privileges only; audit table `SELECT, INSERT`; not superuser, no `BYPASSRLS`/`CREATEROLE`/`CREATEDB`; cannot alter, drop or disable triggers |

Run `migrate` as the owner with `DJANGO_DB_RUNTIME_ROLE` set (grants are re-applied after every
migration). Verify with `python manage.py verify_runtime_privileges` using the runtime role's
`DATABASE_URL`. Database superusers and the owner role remain able to bypass application-level
controls; protect those credentials accordingly.

## Production configuration requirements

`config.settings.production` refuses to start unless all of the following hold:

| Setting | Requirement |
|---|---|
| `DJANGO_DEBUG` | false |
| `DJANGO_SECRET_KEY` | ≥ 50 random characters, not a placeholder |
| `DJANGO_JWT_SIGNING_KEY` | ≥ 50 random characters, different from `DJANGO_SECRET_KEY` |
| `DJANGO_ALLOWED_HOSTS` | Explicit hosts, no `*` |
| `DJANGO_CORS_ALLOWED_ORIGINS` | Explicit `https://` origins only (or none) |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | Explicit `https://` origins only, no wildcards (AEMS-026) |
| `AEMS_FRONTEND_BASE_URL` | `https://` origin (emailed links carry one-time tokens) |
| `EMAIL_URL` | `smtp+tls://` or `smtps://` (AEMS-023); plain `smtp://` only with `AEMS_EMAIL_ALLOW_UNENCRYPTED_SMTP=true` on an isolated test network |
| `DJANGO_API_DOCS_ENABLED` | false |
| `DJANGO_PASSWORD_MIN_LENGTH` | ≥ 12 |
| Refresh cookie | `Secure` |
| `DATABASE_URL` | PostgreSQL, using the runtime role |

Production also enables:

- HTTPS redirect;
- HSTS for one year, with subdomains and preload;
- `Secure`, `SameSite=Strict` session and CSRF cookies;
- `X-Frame-Options: DENY` and `nosniff`;
- `Referrer-Policy: strict-origin-when-cross-origin`;
- `Cross-Origin-Opener-Policy: same-origin`.

`manage.py check --deploy --fail-level WARNING` must pass. It fails, for example, when HSTS or the
HTTPS redirect is disabled.

Behind a reverse proxy:

- Set `DJANGO_BEHIND_TLS_PROXY=true` only when the proxy strips and overwrites
  `X-Forwarded-Proto`.
- Set `DJANGO_TRUSTED_PROXY_COUNT` to the exact number of proxies that append to
  `X-Forwarded-For`.

With both unset, forwarded headers are ignored.

## Secret management

- All secrets come from the environment. Nothing secret is committed; `detect-secrets` runs in CI
  with a reviewed baseline.
- Generate `DJANGO_SECRET_KEY` and `DJANGO_JWT_SIGNING_KEY` independently, for example with
  `python -c "import secrets; print(secrets.token_urlsafe(64))"`, and store them in the
  platform's secret store.
- **Rotating `DJANGO_JWT_SIGNING_KEY`** invalidates every access and refresh token: all users must
  sign in again.
- **Rotating `DJANGO_SECRET_KEY`** invalidates outstanding password-reset links and changes the
  rate-limiter digests: counters effectively reset.
- Database, SMTP and secret-store credentials should be scoped to the application. The owner
  role's credentials belong only to the migration job.

## Secure email configuration

Invitation and password-reset emails contain one-time links. Deployments must:

1. Use an SMTP provider over TLS (`smtp+tls://user:password@host:587` or `smtps://...:465`), with
   credentials supplied through `EMAIL_URL` in the secret store.
2. Send from a domain they control (`DEFAULT_FROM_EMAIL`) and authenticate it:
   - **SPF:** a TXT record authorizing only the provider's sending hosts, ending in `-all` once
     verified (start with `~all` while testing).
   - **DKIM:** signing enabled at the provider, with the published selector record (2048-bit keys
     where supported).
   - **DMARC:** a `_dmarc` TXT record. Start with `p=none` and aggregate reporting (`rua=`), then
     move to `p=quarantine` or `p=reject` once SPF and DKIM pass consistently.
3. Keep `AEMS_FRONTEND_BASE_URL` on HTTPS: tokens travel in the URL fragment, which is never sent
   to servers or in `Referer`, but the page itself must be served securely.

No real email infrastructure is configured by this repository. Local development and CI use
Mailpit.

## Outbox delivery commands

Requests only **queue** emails; two management commands deliver them. Neither command sends mail
during a web request. Both are safe to run concurrently, because rows are claimed with
`SELECT … FOR UPDATE SKIP LOCKED` under a lease.

| Command | Delivers | Notes |
|---|---|---|
| `python manage.py deliver_password_reset_emails` | Password-reset emails (ADR-0014) | Rows expire after `AEMS_PASSWORD_RESET_EMAIL_TTL_SECONDS` (15 min); finished rows are purged after 7 days |
| `python manage.py deliver_invitation_emails` | Invitation emails (ADR-0018) | A fresh token is issued at send time; every send rotates it, so only the latest link works |

Operational guidance:

- **Schedule both every minute**, with the same image and environment as the web process, as
  short-lived jobs (cron, a Kubernetes `CronJob`, or a platform scheduler). Each run is bounded by
  `--batch-size` (default 100, maximum 1000).
- **Time limits:**
  - Give each job a timeout comfortably above `batch-size × EMAIL_TIMEOUT` (10 s per SMTP
    operation).
  - A killed run is safe: its claims expire after the 120 s lease and are retried.
  - A row claimed more than `max_attempts` times without an outcome is failed as `abandoned`
    instead of being resent (AEMS-024).
- **Retries:**
  - Transient failures are retried with exponential backoff (60 s base, 15 min cap), up to
    `AEMS_*_EMAIL_MAX_ATTEMPTS` (5).
  - A refused recipient fails immediately.
- **Monitoring:**
  - `--status` prints queue counts as JSON, and never addresses or tokens. Alert when the oldest
    pending row grows older than a few minutes, or when `failed` counts rise.
  - Audit events `invitation.delivery_failed`, `auth.password_reset.delivery_failed` and
    `invitation.delivery_lease_lost` carry sanitized failure categories only.
- **Diagnostics:**
  - Command output contains counts only.
  - SMTP error messages are never stored, because they can contain addresses.
  - To investigate, use the provider's logs.
- Delivery is at least once: a crash after the SMTP server accepted a message can cause a
  duplicate. For invitations, only the latest link works.

## Log and audit review

- **Request logs:**
  - Logs are structured JSON with a request id, which also appears in every error response.
  - Request logs record the route pattern, never the raw path or query string.
  - Sensitive keys, bearer and basic credentials, and JWT-shaped values are redacted.
- **Security events** worth alerting on:

  | Event | Action |
  |---|---|
  | `auth.refresh.reuse_detected` | Investigate as possible token theft |
  | `auth.session.owner_mismatch` | Investigate as a possible signing-key compromise or defect |
  | `auth.rate_limited`, `auth.login.locked`, `auth.admin_login.rate_limited`, `auth.admin_login.failed` | Watch for spikes (repeated refusals appear in the log stream with `repeated: true`) |
  | `auth.csrf.failed` | Watch for spikes |
  | `tenant.access_denied` | Watch for enumeration attempts by an account |
  | `invitation.accept_rejected` | Watch for spikes |
  | `security.public_access_blocked`, `security.public_endpoint_not_allowlisted` | Treat as a configuration defect |

- **Audit history:**
  - Tenants read their organization's history at `GET /api/v1/organizations/{id}/audit-logs/`
    (`audit.view`).
  - Platform events need `GET /api/v1/platform/audit-logs/` and the `audit.view_auditlog` model
    permission.
  - Review platform administrator actions: organization creation and suspension, initial Owner
    invitations, admin account changes (`auth.account.updated`, including email changes) and
    `auth.password.changed_by_admin`.

## Incident response considerations

| Situation | Response |
|---|---|
| Suspected token theft | Revoke the user's sessions (admin action, or have the user revoke other sessions or change their password). Refresh-token replay already revokes the affected session automatically. |
| Suspected account compromise | Deactivate the account (`deactivate_user`, via the admin). Deactivation is refused if the account is the last active Owner of an organization: assign another Owner first. |
| Signing-key exposure | Rotate `DJANGO_JWT_SIGNING_KEY`, which invalidates all tokens. If `DJANGO_SECRET_KEY` was exposed, rotate it as well. |
| Database credential exposure | Rotate the role's password. If the owner role was exposed, assume the audit trail and triggers may have been tampered with, and compare against backups. |
| Email account compromise | Rotate SMTP credentials, revoke pending invitations and reissue them. Pending password-reset rows expire within 15 minutes. |
| Evidence | Audit rows are append-only. Preserve database backups and logs before remediation. |

## Data retention (current behaviour and recommendations)

No destructive cleanup of invitations or audit rows exists. Phase 1 does not introduce one: it
would conflict with the invitation terminal-state trigger and the append-only audit design.

| Data | Current behaviour | Recommendation (requires a decision) |
|---|---|---|
| Expired pending invitations | Remain `pending` until replaced (then marked `expired`); unusable after expiry | Periodically mark expired, without deleting |
| Accepted and revoked invitations | Kept indefinitely; rows are immutable | Retain for the organization's lifetime; consider archival in a later phase |
| Invitation email outbox | Kept indefinitely; no address, token or body stored | Purge finished rows after 30-90 days |
| Password-reset outbox | Finished rows purged after 7 days by the delivery command | Keep |
| Rate-limit counters and backoff | Purge with `purge_auth_rate_limits` | Schedule daily |
| Authentication security events | Durable audit rows, bounded per window for refusals | Retain 1 year (organization policy) |
| Durable audit log | Append-only, kept indefinitely | Define retention and archival together with legal requirements before Phase 2 data |

Approved decisions retained from Batch 7:

- Historical invitation role links may disappear after a custom role is deleted, while the audit
  records keep the role ids.
- Immutable historical role snapshots are deferred.
- Invitation tokens are issued at delivery time.
- Existing users must authenticate to accept an invitation.
- Acceptance does not issue a session.

## Known security limitations

These are deliberate Phase 1 scope limits or residual risks, not open defects:

| Limitation | Notes |
|---|---|
| No PostgreSQL row-level security | Isolation is enforced by the application, plus composite foreign keys where rows reference each other. A decision on RLS is a **Phase 2 prerequisite** before student, examination or response data is stored (ADR-0003). |
| Tenant reassignment of unreferenced rows | Application-level only; raw SQL by a privileged database role could move a row that nothing references. |
| Database superuser and owner role | Can bypass triggers and privileges. The audit log is tamper-resistant against the application, not against database administrators; hash chaining and external archival are deferred. |
| No MFA, SSO or account lockout notifications | Out of scope for Phase 1. |
| Platform RBAC administration | Platform authority uses Django model permissions managed by superusers in the admin. |
| Organization reactivation | `suspended → active` is unavailable. |
| Authenticated audit growth | Signed-in users can generate audit events (for example `tenant.access_denied`) at the rate of their requests. Rate limiting covers only the public endpoints. |
| Fixed-window rate limits | A burst at a window boundary can reach twice the per-window limit. Limits are per IP and per account, not global. |
| Timing | Responses avoid observable differences such as SMTP calls, but the endpoints are not constant time. |
| Email delivery | At least once; deliverability depends on SPF, DKIM and DMARC configured by the operator. |
| No deployment | No WAF, TLS termination, backups or monitoring are provided by this repository. |
