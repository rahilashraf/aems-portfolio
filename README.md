# AEMS — Assessment & Examination Management System

AEMS is a multi-organization SaaS platform for schools, universities, and training organizations,
supporting online and paper-based examinations with strict tenant isolation and customizable,
organization-scoped roles and permissions.

> **Status:** Phase 1 — Backend Foundation, Batch 7 (invitations and organization onboarding).
> See the [Phase 1 plan](docs/phase-1-plan.md) and [Architecture Decision Records](docs/adr/README.md).

## Technology

| Layer | Stack |
|---|---|
| Backend | Python 3.13, Django 5.2 LTS, Django REST Framework, django-filter, drf-spectacular, structlog |
| Database | PostgreSQL 17 |
| Frontend | Next.js, React, TypeScript (after backend approval) |
| Tooling | uv, ruff, mypy (strict), pytest, bandit, pip-audit, pre-commit |
| Dev environment | Docker Compose (PostgreSQL, backend, Mailpit) |
| CI | GitHub Actions ([Backend CI](.github/workflows/backend-ci.yml)), Dependabot |

## Repository layout

```
backend/            Django project
  config/           settings (base/local/test/production), URLs, WSGI/ASGI
  apps/core/        shared infrastructure: health checks, base models, request context,
                    structured logging, Problem Details errors, API conventions, OpenAPI
  tests/            test-only fixture app (never installed outside the test settings)
docker/postgres/    database bootstrap scripts (least-privilege runtime role)
docs/               Phase plan, ADRs, committed OpenAPI schema (docs/api/openapi.yaml)
.github/            CI workflow, Dependabot, PR template
docker-compose.yml  local development stack
Makefile            developer commands (`make help`)
```

## Quick start (Docker)

Prerequisites: Docker with Compose v2, GNU Make.

```bash
cp .env.example .env     # development-only defaults; edit as needed
make up                  # builds and starts db, backend, mailpit
```

| Service | URL |
|---|---|
| API root | http://localhost:8000/api/v1/ |
| API docs (Swagger UI / ReDoc) | http://localhost:8000/api/docs/ · http://localhost:8000/api/redoc/ |
| OpenAPI schema | http://localhost:8000/api/schema/ |
| Backend liveness | http://localhost:8000/health/live/ |
| Backend readiness | http://localhost:8000/health/ready/ |
| Mailpit (email UI) | http://localhost:8025/ |
| Mailpit SMTP (host-based Django) | `localhost:1025` |

All ports bind to `127.0.0.1` only; override them with the `*_HOST_PORT` variables in `.env`.
Containerized Django sends mail to `mailpit:1025`; host-based Django uses `EMAIL_URL` from `.env`
(`smtp://localhost:1025`). To check delivery, run `make sendtestemail` (host) or
`docker compose exec backend python manage.py sendtestemail dev@example.test` and open the
Mailpit UI.

Run the tests inside the container:

```bash
make docker-test
```

Stop the stack (database data is kept in a named volume):

```bash
make down
```

## Host development (faster feedback)

Prerequisites: [uv](https://docs.astral.sh/uv/) and Python 3.13. The database still runs in Docker.

```bash
make env install hooks   # .env, dependencies, git hooks
docker compose up -d db mailpit
make migrate             # apply migrations as the owner role (DATABASE_OWNER_URL)
make test                # pytest + coverage gate (90%)
make qa                  # every quality gate
```

Create a platform administrator, then sign in at http://localhost:8000/admin/ (path configurable
with `DJANGO_ADMIN_URL`):

```bash
uv --directory backend run python manage.py createsuperuser
```

Variables passed on the command line or in the environment override `.env` for `make` targets, for
example `DATABASE_OWNER_URL=postgres://... make migrate` migrates that database.

**Two database roles** ([ADR-0016](docs/adr/0016-durable-audit-logging.md)):
- `DATABASE_URL` (`aems_app`) is the **runtime** role the application uses. It owns nothing.
- `DATABASE_OWNER_URL` (`aems_owner`) owns the schema. `make migrate`, `make test` and the drift
  checks connect with it.

After every migrate, the runtime role named by `DJANGO_DB_RUNTIME_ROLE` is granted its
privileges, with read and append only on the audit log. `make verify-runtime-privileges` checks
them.

Databases created before Batch 5 (where `aems_app` owns everything) need a one-time upgrade, run as
a superuser, then `make migrate`:

```bash
docker compose exec -T db psql -U postgres -d aems -v owner_user=aems_owner -v owner_password=dev-only-owner-password -v app_user=aems_app -v app_db=aems -f - < docker/postgres/upgrade/batch-5-role-split.sql
```

Alternatively, recreate the volume with `docker compose down -v`, which deletes local data.

| Command | Purpose |
|---|---|
| `make test` | Tests with branch coverage; fails below 90% (extra pytest args: `PYTEST_ARGS=...`) |
| `make lint` / `make format` | ruff lint + formatting |
| `make typecheck` | mypy (strict) with django-stubs and DRF stubs |
| `make check` | Django system checks, including the public-endpoint allowlist |
| `make security` | bandit static analysis |
| `make audit` | pip-audit against the locked dependency set |
| `make secrets` | detect-secrets scan against `.secrets.baseline` (offline: `--no-verify`, so results never depend on network access) |
| `make check-migrations` | Fails if models and migrations diverge |
| `make check-no-auth-tables` | Fails if Django's default `auth_user` tables exist |
| `make schema` | Regenerates `docs/api/openapi.yaml` |
| `make schema-check` | Fails if the committed schema differs from the generated one |
| `make deploy-check` | `manage.py check --deploy` against production settings |
| `make qa` | Every local quality gate |

## API

The REST API is versioned by URL path: `/api/v1/`. Conventions (details in the ADRs):

- **JSON only**: requests are parsed as JSON (`415` otherwise); responses are JSON; datetimes
  are ISO 8601 UTC.
- **Deny by default**: an endpoint without explicit permissions is unreachable. Public endpoints
  use `PublicEndpoint` **and** must be listed in `API_PUBLIC_ENDPOINTS`. Every DRF view uses
  the project base classes (`AemsAPIView` and others), whose runtime guard refuses unauthenticated
  access to any non-allowlisted endpoint. System checks `core.E001`–`core.E005` catch
  misconfiguration at startup ([ADR-0012](docs/adr/0012-api-access-control-enforcement.md)).
  Every other endpoint requires a valid access token; unauthenticated requests receive
  `401 not_authenticated` with `WWW-Authenticate: Bearer realm="api"`.
- **Errors**: RFC 9457 Problem Details (`application/problem+json`) with a stable `code` and the
  `request_id` ([ADR-0009](docs/adr/0009-api-error-response-conventions.md)). `WWW-Authenticate`,
  `Retry-After` and `Allow` headers are preserved.
- **Request IDs**: every response carries `X-Request-ID`. A valid client-supplied ID (8–128
  characters of `A-Z a-z 0-9 . _ : -`) is propagated; otherwise a UUIDv4 is generated
  ([ADR-0010](docs/adr/0010-request-correlation-and-structured-logging.md)).
- **Pagination**: `?page=` and `?page_size=` (default 25, maximum 100; larger values are capped).
  Responses contain `count`, `page`, `page_size`, `total_pages`, `next`, `previous` and `results`.
  An invalid value returns `400 invalid_query_parameters`; a page past the end returns
  `404 page_not_found`.
- **Filtering and ordering**: only explicitly allowlisted fields. An unknown `?ordering=` field
  returns 400. Ordering always ends with the primary key, so pages are stable.

| Endpoint | Description | Access |
|---|---|---|
| `GET /api/v1/` | API root (service name and API version) | Public |
| `/api/v1/auth/...` | Authentication, profile, passwords and sessions (see below) | Mixed |
| `/api/v1/organizations/...` | The caller's organizations and tenant APIs (see below) | Bearer + membership |
| `/api/v1/platform/organizations/...` | Organization administration (see below) | Platform administrators |
| `/api/v1/organizations/{org_id}/members/`, `roles/`, `permissions/` | Members, roles and the permission catalog (see below) | Organization permissions |
| `/api/v1/organizations/{org_id}/audit-logs/`, `/api/v1/platform/audit-logs/` | Audit history (see below) | `audit.view` / platform auditors |
| `GET /api/schema/` | OpenAPI 3 schema | Public when `API_DOCS_ENABLED`; always 404 in production |
| `GET /api/docs/`, `GET /api/redoc/` | Swagger UI / ReDoc | Same as above |

The committed contract lives at [`docs/api/openapi.yaml`](docs/api/openapi.yaml). Regenerate it
with `make schema`; CI fails if it is stale.

## Authentication

Design: [ADR-0004](docs/adr/0004-authentication-and-session-management.md) and
[ADR-0013](docs/adr/0013-authentication-implementation-and-security-events.md).

- **Access token**: a JWT valid for 10 minutes, returned in the JSON body and sent as
  `Authorization: Bearer <token>`. Clients keep it in memory only, never in
  `localStorage`/`sessionStorage`.
- **Refresh token**: kept only in the `aems_refresh` cookie (`HttpOnly`, `Secure`,
  `SameSite=Strict`, `Path=/api/v1/auth/`). It is never in a response body. It lasts 7 days and is
  rotated on every refresh; each sign-in session has an absolute lifetime of 30 days.
- **Server-side sessions**: each sign-in creates an `AuthSession`. Every request checks that the
  session and user are still valid, so logout, password changes, deactivation and replay detection
  take effect **immediately**. Reusing an already-rotated refresh token revokes the whole session.
- **CSRF**: cookie-authenticated calls (refresh, and logout with the cookie) require the
  `X-CSRFToken` header (the `csrftoken` cookie value from `GET /api/v1/auth/csrf/`) and a
  same-origin `Origin`/`Referer`.
- **Abuse protection**: atomic PostgreSQL rate limits per IP and account, plus a temporary
  exponential lockout after repeated failures. Responses never reveal whether an account exists.

| Endpoint | Purpose | Access |
|---|---|---|
| `GET /api/v1/auth/csrf/` | Set the CSRF cookie | Public |
| `POST /api/v1/auth/login/` | Sign in (`email`, `password`) → access token + refresh cookie | Public |
| `POST /api/v1/auth/token/refresh/` | Rotate the refresh cookie → new access token | Refresh cookie + CSRF |
| `POST /api/v1/auth/logout/` | Revoke the current session, clear the cookie | Refresh cookie + CSRF, or bearer |
| `GET`, `PATCH /api/v1/auth/me/` | Own profile (only `full_name` is editable) | Bearer |
| `POST /api/v1/auth/password/change/` | Change password; revokes all sessions, returns new tokens | Bearer |
| `POST /api/v1/auth/password/reset/` | Queue a reset email (always `202`; see below) | Public |
| `POST /api/v1/auth/password/reset/confirm/` | Set a new password (`uid`, `token`, `new_password`) | Public |
| `GET /api/v1/auth/sessions/` | List own active sessions | Bearer |
| `DELETE /api/v1/auth/sessions/{id}/` | Revoke one own session | Bearer |
| `POST /api/v1/auth/sessions/revoke-others/` | Revoke all own sessions except the current one | Bearer |

There is no self-service registration. Accounts are created by platform administrators or by
accepting an organization invitation (see [Invitations and onboarding](#invitations-and-onboarding)).

### Password-reset email delivery

`POST /api/v1/auth/password/reset/` **queues** the email and returns `202`. It never contacts the
mail server, so the response, its headers and its timing do not depend on SMTP or on whether the
account exists. A `202` means **accepted, not delivered**. Responses are not mathematically
constant-time: small database differences remain. See
[ADR-0014](docs/adr/0014-password-reset-email-outbox.md).

Emails are sent only when the delivery command runs:

```bash
python manage.py deliver_password_reset_emails            # send due emails (bounded batch)
python manage.py deliver_password_reset_emails --status   # queue counts as JSON (no personal data)
```

- **Locally:** `make deliver-reset-emails` (host) or `make docker-deliver-reset-emails`
  (container), then open Mailpit at http://localhost:8025/. The link carries its token in the URL
  fragment.
- **Production:** no scheduler is configured yet (deployment is deferred). Run the command
  regularly, for example every minute from cron, a systemd timer or a Kubernetes `CronJob`, using
  the application image and settings. Runs are bounded and safe to overlap.
- **If it is not running:** requests are still accepted but **no email is sent**. Unsent requests
  expire after 15 minutes (`AEMS_PASSWORD_RESET_EMAIL_TTL_SECONDS`) and are not sent later.
- **What is stored:** the outbox holds no address, token or message body. Failures are retried
  with backoff (up to `AEMS_PASSWORD_RESET_EMAIL_MAX_ATTEMPTS`) and logged as sanitized
  categories. Delivery is at least once, so a crash at the wrong moment can send a duplicate;
  every link is still single-use and expiring.

Expired rate-limit records can be removed with `python manage.py purge_auth_rate_limits`.

## Organizations and tenancy

AEMS uses **shared-schema multi-tenancy**: one database and schema, with every tenant-owned row
carrying a non-null `organization_id`. Users are global, and one user can be a member of several
organizations ([ADR-0003](docs/adr/0003-tenant-isolation.md),
[ADR-0015](docs/adr/0015-organizations-and-tenancy-implementation.md)).

- **The tenant comes from the URL only:** `/api/v1/organizations/{org_id}/…`. Request bodies may
  not name an organization (400), and headers are ignored.
- **Every tenant request** resolves the caller's active membership in an active organization. An
  unknown organization, another tenant's organization, a provisioning or suspended organization,
  a suspended membership and a platform administrator without a membership all receive the
  **same 404**.
- **Authorization is default deny.** Every active member may read their own `me/`. Anything else needs an organization permission granted by the member's roles in that
  organization (see [Roles and permissions](#roles-and-permissions)).
- **Lifecycle.** New organizations start in `provisioning` and are closed to tenant APIs. They
  become `active` only when the initial Owner accepts their invitation (see
  [Invitations and onboarding](#invitations-and-onboarding)); there is **no manual activation**.
  Platform administrators can suspend an active organization, which closes its
  tenant APIs immediately. Reactivation is not available yet (it needs a verified Owner).
- **Row-level security** is deferred to Phase 2, behind a security review (ADR-0003).

| Endpoint | Purpose | Access |
|---|---|---|
| `GET /api/v1/organizations/` | My organizations: active memberships in active organizations | Bearer |
| `GET /api/v1/organizations/{org_id}/` | Organization profile | `organization.view` (default Member role) |
| `PATCH /api/v1/organizations/{org_id}/` | Update `name`/`timezone` | `organization.update` |
| `GET /api/v1/organizations/{org_id}/me/` | My membership, roles and effective permissions | Active member |
| `GET`, `POST /api/v1/platform/organizations/` | List (filter `status`, `organization_type`; order `name`, `slug`, `created_at`, `status`) or create (`name`, `slug`, `organization_type`, `timezone`, `initial_owner_email`) | Platform administrator |
| `GET`, `PATCH /api/v1/platform/organizations/{id}/` | Retrieve or update (`name`, `organization_type`, `timezone`, `status`: `active` → `suspended` only) | Platform administrator |

A **platform administrator** is an active staff account holding the matching Django permission
(`organizations.view_organization`, `add_organization` or `change_organization`; superusers hold
all). Grant these in the admin. Platform administration gives no access to tenant data.


**Writing tenant endpoints.** Subclass `OrganizationScopedViewMixin` before the base view. Set
`tenant_model` and `permission_classes = [HasOrgPermission]`, and declare `member_actions`
(read-only) and `required_permissions`. Read data only through `get_scoped_queryset()`,
`get_scoped_object_or_404()` and `TenantScopedPrimaryKeyRelatedField`. The route-coverage
meta-test (`apps/organizations/tests/test_route_coverage.py`) fails for routes that do not.

**Tests.** `apps/organizations/tests/` contains the tenant-isolation matrix and the route
meta-test. Active organizations in tests come from a test-only fixture, because production code
cannot activate one.

## Roles and permissions

Each organization has its own roles ([ADR-0005](docs/adr/0005-rbac-and-ownership-invariants.md),
[ADR-0017](docs/adr/0017-organization-rbac-implementation.md)). A user can hold different roles
in different organizations, and a role never grants anything in another organization. Django's
global groups and staff permissions play no part.

- **Permission catalog** (registered in code, synced after every `migrate`): `organization.view`,
  `organization.update`, `members.view`, `members.manage`, `invitations.manage` (Batch 7),
  `roles.view`, `roles.manage`, `audit.view`. Codes are immutable; retired codes are deprecated,
  never deleted, and grant nothing.
- **System roles**, seeded for every organization:
  - **Owner** holds every permission, including ones added later, and cannot be edited or
    deleted;
  - **Admin** (default: all permissions) and **Member** (default: `organization.view`) have
    editable permissions but fixed names.

  Custom roles can hold any catalog permissions.
- **Owner invariant.** An active organization always keeps at least one active Owner. Suspending
  or removing a member, removing the Owner role and deactivating an account (also from the staff
  admin) are refused with `409 last_owner` when they would break it.
- **Escalation rules.**
  - Nobody can change their own status or roles; an Owner may give up the Owner role while
    another Owner remains.
  - You can only grant, remove or act on permissions you hold, including through a role you hold
    yourself.
  - Only Owners grant or remove the Owner role or change an Owner.
- **Concurrency.** Every change locks the organization row and re-checks the actor's
  permissions from the database before applying anything, so a permission revoked mid-request
  cannot be used. Lock order: user → organizations (ascending id) → memberships (ascending id).
- **Audit.** Every change is recorded in the same transaction (`rbac.*` events).

| Endpoint | Purpose | Permission |
|---|---|---|
| `GET /api/v1/organizations/{org_id}/members/` | List members with their roles (filter `status`, order `joined_at`) | `members.view` |
| `GET /api/v1/organizations/{org_id}/members/{id}/` | One member | `members.view` |
| `PATCH /api/v1/organizations/{org_id}/members/{id}/` | `status`: `active` or `suspended` | `members.manage` |
| `DELETE /api/v1/organizations/{org_id}/members/{id}/` | Remove the membership (the account is kept) | `members.manage` |
| `PUT /api/v1/organizations/{org_id}/members/{id}/roles/` | Replace the member's roles (`role_ids`) | `members.manage` + delegation/Owner rules |
| `GET`, `POST /api/v1/organizations/{org_id}/roles/` | List (filter `is_system`, order `name`, `created_at`) or create (`name`, `description`, `permissions`) | `roles.view` / `roles.manage` |
| `GET`, `PATCH`, `DELETE /api/v1/organizations/{org_id}/roles/{id}/` | Read, edit or delete a role (assigned and system roles cannot be deleted) | `roles.view` / `roles.manage` |
| `GET /api/v1/organizations/{org_id}/permissions/` | Assignable catalog permissions | `roles.view` |

Organizations created before Batch 6 receive the three system roles by migration, but nobody is
made an Owner: Owners come from an existing Owner or the initial Owner invitation.

## Invitations and onboarding

People join organizations only by invitation ([ADR-0018](docs/adr/0018-invitations-and-onboarding.md)).

- **Initial Owner.** Creating an organization (`POST /api/v1/platform/organizations/` with
  `initial_owner_email`) creates it `provisioning`, with its roles and an invitation granting the
  Owner role, in one transaction. Accepting that invitation creates the Owner membership and makes
  the organization `active`. That is the only activation path.
- **Member invitations.** Members with `invitations.manage` invite people with roles whose
  permissions they hold (Owner role: Owners only). When the invitation is accepted, the
  inviter's authority is checked again; if it has shrunk, acceptance fails
  (`invitation_authority_revoked`).
- **Tokens.** Each token is 256 random bits, sent only by email in the link's URL fragment. Only
  its SHA-256 digest is stored, and it never appears in API responses, logs or audit records. It
  expires after 7 days, is single use and can be revoked. Each email carries a fresh token, so
  only the latest link works.
- **Accepting.**
  - If an account exists for the invited address, sign in as it and send an empty body.
  - Otherwise, send `full_name` and `password` to create the account with the invited address.
  - Membership, roles, invitation consumption and activation commit together, with their audit
    records.
- **Email delivery** works like the password-reset outbox: invitations are queued in their
  transaction and sent by `python manage.py deliver_invitation_emails`, run regularly (for example
  every minute). Use `--status` for counts. Failures retry with backoff; `delivery_status`
  reports `pending`, `delivered`, `failed` or `cancelled`.

| Endpoint | Purpose | Access |
|---|---|---|
| `GET`, `POST /api/v1/organizations/{org_id}/invitations/` | List (filter `status`; never tokens) or invite (`email`, `role_ids`) | `invitations.manage` |
| `POST /api/v1/organizations/{org_id}/invitations/{id}/revoke/` | Revoke a pending invitation | `invitations.manage` + authority over its roles |
| `GET`, `POST /api/v1/platform/organizations/{id}/initial-owner-invitation/` | View, or revoke and reissue, the initial Owner invitation (provisioning only) | `view_organization` / `manage_initial_owner_invitation` |
| `POST /api/v1/platform/organizations/{id}/initial-owner-invitation/revoke/` | Revoke the initial Owner invitation | `manage_initial_owner_invitation` |
| `GET /api/v1/invitations/{token}/` | Preview: organization name, masked address, expiry, next step | Public (token) |
| `POST /api/v1/invitations/{token}/accept/` | Accept (existing account: bearer; new account: `full_name`, `password`) | Public (token) |

The public routes return the same `404 invitation_invalid` for every unusable token, are rate
limited per IP, and are sent with `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.

## Audit log

Security-relevant actions are stored in an append-only `AuditLog`
([ADR-0006](docs/adr/0006-audit-logging.md), [ADR-0016](docs/adr/0016-durable-audit-logging.md)).

- **Mutations are atomic with their records.** Services call `audit.record()` inside the
  transaction that makes the change, so a committed change always has its record and a rolled-back
  change has none. If the audit insert fails, the change does not commit.
- **Failures are recorded independently.** Failed logins, rate limiting, invalid or replayed
  tokens, CSRF failures and denied tenant access go through `audit.record_security_event()`, in
  their own transaction, after any failed operation has rolled back.
- **Append-only.**
  - The model and queryset refuse changes and deletes.
  - A PostgreSQL trigger rejects `UPDATE`/`DELETE` even from raw SQL.
  - The runtime role holds only `SELECT`/`INSERT` and owns nothing.
  - The admin is read-only.

  A superuser or the table owner can still disable the trigger, so protecting history from
  database administrators is an operational matter.
- **No secrets.** Metadata keys and changed fields are allowlisted and validated; text is
  scrubbed and bounded; password changes are stored as "changed" without values.
- **Not yet implemented:** retention, archival and hash chaining.

| Endpoint | Returns | Access |
|---|---|---|
| `GET /api/v1/organizations/{org_id}/audit-logs/` | The organization's events. Filters: `action`, `actor`, `outcome`, `created_after`, `created_before`; cursor pagination, newest first | Non-members: 404. Members need `audit.view` (Owner; Admin by default; any role granting it) |
| `GET /api/v1/platform/audit-logs/` | Events without an organization (accounts, authentication, platform actions, denied tenant access); same filters | Active staff with `audit.view_auditlog` |

Organization events, including changes made by platform staff, belong to that organization's
history. Account and authentication events, and denied tenant access, belong to no organization.

## Health endpoints

| Endpoint | Meaning | Checks |
|---|---|---|
| `GET /health/live/` | Process is up | none (never touches dependencies) |
| `GET /health/ready/` | Ready to serve traffic | PostgreSQL `SELECT 1`; returns `503` if unavailable |

Responses are uncached and never include internal error details.

## Configuration

All configuration comes from environment variables (see [`.env.example`](.env.example)).

| Variable | Default | Purpose |
|---|---|---|
| `DJANGO_LOG_FORMAT` | `json` (`console` in local settings) | Log rendering |
| `DJANGO_LOG_LEVEL` | `INFO` | Root log level (SQL logging is always suppressed) |
| `DJANGO_API_DOCS_ENABLED` | `false` (`true` in local settings) | Serve schema/Swagger/ReDoc; production refuses `true` |
| `DJANGO_CORS_ALLOWED_ORIGINS` | none (`http://localhost:3000` locally) | Explicit origin allowlist; no wildcards; HTTPS required in production |
| `DJANGO_CORS_ALLOW_CREDENTIALS` | `false` | Cross-origin cookies (set `true` when the frontend runs on another origin) |
| `DJANGO_JWT_SIGNING_KEY` | — (required) | Dedicated JWT signing key; production requires 50+ random characters, different from `DJANGO_SECRET_KEY` |
| `DJANGO_JWT_ISSUER` / `DJANGO_JWT_AUDIENCE` | unset | Optional `iss`/`aud` claims, enforced when set |
| `DJANGO_PASSWORD_MIN_LENGTH` | `12` | Minimum password length (production refuses less than 12) |
| `DJANGO_PASSWORD_RESET_TIMEOUT` | `3600` | Reset-link lifetime in seconds |
| `AEMS_FRONTEND_BASE_URL` | `http://localhost:3000` | Base URL of password-reset and invitation links; production requires `https://` |
| `AEMS_INVITATION_TTL_SECONDS` | `604800` (7 days) | Invitation lifetime |
| `AEMS_INVITATION_EMAIL_MAX_ATTEMPTS` | `5` | Delivery attempts before a queued invitation email is marked failed |
| `AEMS_PASSWORD_RESET_EMAIL_TTL_SECONDS` | `900` | Queued reset emails not sent within this time are discarded |
| `AEMS_PASSWORD_RESET_EMAIL_MAX_ATTEMPTS` | `5` | Delivery attempts before a queued email is marked failed |
| `DJANGO_AUTH_REFRESH_COOKIE_SECURE` | `true` (`false` in local settings) | Secure flag on the refresh cookie (production requires `true`) |
| `DJANGO_TRUSTED_PROXY_COUNT` | `0` | Number of trusted reverse proxies whose `X-Forwarded-For` entry is used as the client IP |
| `DJANGO_ADMIN_URL` | `admin/` | Path of the staff-only admin |

Every environment refuses to start unless `DATABASE_URL` resolves to the PostgreSQL backend
(`postgres://`, `postgresql://`, or `pgsql://`); SQLite and other engines are rejected.

### Production configuration

`config.settings.production` refuses to start when:

- `DJANGO_DEBUG` is true (it is validated, never silently overridden);
- `DJANGO_SECRET_KEY` is missing, shorter than 50 characters, low-variety, or a placeholder;
- `DJANGO_ALLOWED_HOSTS` is empty or contains `*`;
- `DJANGO_API_DOCS_ENABLED` is true;
- a CORS origin is a wildcard, `null`, malformed, or not HTTPS;
- `DJANGO_JWT_SIGNING_KEY` is missing, weak, a placeholder, or equal to `DJANGO_SECRET_KEY`;
- the refresh cookie is not `Secure`, or `DJANGO_PASSWORD_MIN_LENGTH` is below 12.

**Trusted TLS proxy (`DJANGO_BEHIND_TLS_PROXY`, default `false`).** When enabled, Django treats a
request as HTTPS if it carries `X-Forwarded-Proto: https`. Enable it **only** when every request
reaches Django through a trusted TLS-terminating reverse proxy (load balancer, ingress) that
**removes any client-supplied `X-Forwarded-Proto` header and overwrites it** with the scheme it
actually received, and when Django is not reachable any other way. Otherwise clients could forge
the header and plain-HTTP requests would be treated as secure.

**Container health check.** The production image's `HEALTHCHECK` runs
[`scripts/healthcheck.py`](backend/scripts/healthcheck.py), which calls `/health/live/` on the
local socket while sending the first `DJANGO_ALLOWED_HOSTS` entry as the `Host` header. Host
validation therefore stays fully enforced: no loopback address or wildcard needs to be added to
`ALLOWED_HOSTS`.

The application connects to PostgreSQL as the non-superuser runtime role (`aems_app`), which owns
no tables. Migrations run as the owner role (`aems_owner`). Both roles are created by
[`docker/postgres/init/01-create-app-role.sh`](docker/postgres/init/01-create-app-role.sh).
Production must provision the same split and run `migrate` with the owner's `DATABASE_URL` and
`DJANGO_DB_RUNTIME_ROLE` set (ADR-0016).

## Continuous integration

[Backend CI](.github/workflows/backend-ci.yml) runs on every pull request to `main` and every
push to `main`, with no path filters ([ADR-0011](docs/adr/0011-continuous-integration.md)):

| Check | Contents |
|---|---|
| Lint & type check | ruff, ruff format, strict mypy, hygiene hooks |
| Tests & migrations | PostgreSQL 17, owner and runtime roles (neither superuser), fresh migrate as owner, no default auth tables, runtime privileges verified, migration drift, full suite with 90% branch coverage (including runtime-role privilege tests), coverage artifact |
| Security | Bandit, pip-audit, detect-secrets, production `check --deploy` |
| API contract | OpenAPI generation, validation and drift check |
| Docker image | clean build of the committed Dockerfile, non-root, container becomes `healthy`, endpoint behaviour, password reset and initial Owner onboarding through Mailpit, audit and RBAC database safeguards |
| Backend CI result | passes only if every job above passed (recommended required check) |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Copyright (c) 2026 Rahil Ashraf. All rights reserved.

AEMS is publicly available for portfolio demonstration and educational reference. Public
availability does not grant permission to reuse, redistribute, modify, or commercially exploit the
source code. See [LICENSE](LICENSE) for details.

Third-party dependencies are licensed separately under their own terms, which this notice does not
replace or modify.
