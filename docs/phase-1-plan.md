# AEMS — Phase 1 Backend Foundation Plan

| | |
|---|---|
| **Status** | Approved with required corrections (incorporated below) |
| **Phase** | 1 — Backend Foundation |
| **Scope** | Backend only. No frontend, no examination/assessment domain, no deployment. |
| **Related ADRs** | [docs/adr/](adr/README.md) |

AEMS (Assessment & Examination Management System) is a multi-organization SaaS platform for
schools, universities, and training organizations. Phase 1 builds the secure, multi-tenant
foundation that every later phase depends on: identity, organizations, tenant isolation,
customizable roles and permissions, audit logging, API conventions, a reproducible development
environment, automated tests, and CI.

---

## 1. Approved decisions

| # | Decision | Outcome |
|---|---|---|
| D1 | Authentication | JWT access tokens + rotating, HttpOnly refresh-token cookie, backed by server-side sessions ([ADR-0004](adr/0004-authentication-and-session-management.md)) |
| D2 | Organization creation | Platform administrators only during Phase 1 |
| D3 | Email flows | Organization invitations and password reset are in scope; Mailpit for local testing |
| D4 | PostgreSQL RLS | Deferred to Phase 2. A security review and explicit implementation decision is **required** before any sensitive student, examination, or response records are introduced ([ADR-0003](adr/0003-tenant-isolation.md) §RLS requirements) |
| D5 | Framework | Python 3.13, Django 5.2 LTS, compatible maintained dependency versions |
| D6 | Delivery | One reviewable pull request per implementation batch, targeting `main`. Nothing is merged without explicit approval |

### Corrections incorporated in this revision

1. **Case-insensitive email** — no `CIEmailField`/`CITextField` (removed in Django 5.1). Normalized
   `EmailField` + functional unique constraint on `Lower("email")`, with safe handling of
   uniqueness races (§4.1, [ADR-0008](adr/0008-email-identity-normalization.md)).
2. **Authentication hardening** — refresh-token families with atomic rotation and replay
   detection, CSRF on every cookie-authenticated endpoint, no access tokens in `localStorage`,
   authenticated acceptance of invitations by existing users, credential invalidation on password
   change, immediate effect of deactivation, and an atomic database-backed abuse limiter (§4.2–4.5).
3. **Ownership and RBAC consistency** — last-active-Owner invariant enforced under concurrency with
   row locking, no self-promotion, no escalation, Owner-level operations bound by the same
   invariants, concurrency regression tests (§6, [ADR-0005](adr/0005-rbac-and-ownership-invariants.md)).
4. **Tenant isolation** — reaffirmed shared-schema design; documented RLS requirements for Phase 2;
   tenant-isolation tests mandatory (§5).
5. **Audit logging** — atomic with mutations, append-only at application and database level,
   secret redaction, failed-authentication events recorded independently of rolled-back
   transactions (§7, [ADR-0006](adr/0006-audit-logging.md)).
6. **CI** — broadened path triggers, real PostgreSQL, migration verification, authorization and
   isolation suites, lint, types, dependency audit, Docker build, 90% coverage gate, least-privilege
   permissions and SHA-pinned actions (§12).

### Clarifications from the Batch 1 review (documentation only)

These refine designs for later batches; none is implemented in Batch 1.

| Topic | Where | Batch |
|---|---|---|
| Organization provisioning lifecycle (no active organization without an active Owner) | §5.3, §6.3 | 4, 7 |
| Global deactivation across multiple organizations | §4.4, §6.3 | 3, 6 |
| Refresh replay revocation commits even though the API returns 401 | §4.2 | 3 |
| Concurrent changes to the acting user's own permissions | §6.4 | 6 |
| Frontend refresh coordination across browser tabs | §4.2 | frontend phase |

---

## 2. Architecture overview

### 2.1 Repository layout (monorepo)

```
aems-portfolio/
├── backend/                     # Django project (Phase 1)
├── frontend/                    # created only after backend approval
├── docs/
│   ├── phase-1-plan.md          # this document
│   ├── adr/                     # Architecture Decision Records
│   ├── architecture/            # deeper design notes (added per batch)
│   └── api/openapi.yaml         # generated, committed API contract (Batch 2+)
├── docker/postgres/init/        # database bootstrap scripts (dev)
├── .github/                     # workflows (Batch 2), PR template, dependabot
├── docker-compose.yml
├── .env.example
├── Makefile
├── .pre-commit-config.yaml
└── README.md · CONTRIBUTING.md · SECURITY.md (Batch 8)
```

Rationale: a single API contract shared by backend and frontend evolves atomically in one pull
request; one CI configuration; one place for documentation. See [ADR-0002](adr/0002-repository-and-application-architecture.md).

### 2.2 Backend structure

```
backend/
├── pyproject.toml · uv.lock · .python-version
├── Dockerfile                   # multi-stage: base → dev → prod
├── manage.py
├── config/
│   ├── settings/{base,local,test,production}.py
│   ├── urls.py · asgi.py · wsgi.py
└── apps/
    ├── core/            # shared infrastructure only (no domain logic)
    ├── accounts/        # User, authentication, sessions, password flows
    ├── organizations/   # Organization, Membership, Invitation
    ├── rbac/            # permission catalog, roles, evaluation engine
    └── audit/           # AuditLog, audit service, query API
```

Every domain app follows the same internal layout:

```
<app>/
├── models.py
├── services.py      # all writes: transactions, invariants, authorization rules, audit calls
├── selectors.py     # read/query logic
├── api/{serializers,views,urls}.py
├── admin.py
├── migrations/
└── tests/{factories.py, unit/, integration/}
```

Cross-cutting security suites live in `backend/tests/security/`.

**Service layer.** Views and serializers only translate HTTP ↔ Python and validate input. Business
rules, transactions, locking, and audit writes live in `services.py`, so the same rules apply when
later phases call them from background jobs, management commands, or other services.

---

## 3. Dependencies

Runtime (pinned via `uv.lock`; ranges in `pyproject.toml` stay within Django 5.2-compatible lines):

| Package | Purpose | Introduced |
|---|---|---|
| Django `>=5.2,<5.3` (LTS, supported to April 2028) | Framework | Batch 1 |
| psycopg 3 (`psycopg[binary]`) | PostgreSQL driver | Batch 1 |
| django-environ | 12-factor configuration | Batch 1 |
| gunicorn | Production WSGI server (prod image only; no deployment) | Batch 1 |
| djangorestframework | API framework | Batch 2 |
| drf-spectacular | OpenAPI 3 schema + docs UI | Batch 2 |
| structlog / django-structlog | Structured JSON logging with request IDs | Batch 2 |
| django-filter | Filtering | Batch 2 |
| djangorestframework-simplejwt | JWT encoding/validation primitives | Batch 3 |
| argon2-cffi | Argon2id password hashing | Batch 3 |
| django-cors-headers | CORS allowlist (secure defaults; credentials enabled in Batch 3) | Batch 2 |

Development: pytest, pytest-django, pytest-cov, factory-boy, time-machine, ruff, mypy,
django-stubs (5.2 line), djangorestframework-stubs, bandit, pip-audit, pre-commit, detect-secrets.

Dependency management uses **uv** (`pyproject.toml` + `uv.lock`, `uv sync --frozen` in Docker and CI).

Deliberately excluded in Phase 1: Redis/Celery (no async workloads yet), django-tenants (conflicts
with global multi-org users), django-guardian (object-level ACLs not required),
django-auditlog/simple-history (row-diff logging lacks business semantics), the SimpleJWT
blacklist app (replaced by our own session/family model, §4.2).

---

## 4. Identity and authentication

### 4.1 Custom user model (`accounts.User`)

Created in Batch 3 **before any migration that references users**. Batch 1 intentionally installs
no `django.contrib.auth`/`admin` apps so that no default `auth_user` table is ever created.

| Field | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `email` | `EmailField(max_length=254)` | Normalized on write; case-insensitive uniqueness enforced by the database |
| `full_name` | `CharField(255)` | Single name field (international naming) |
| `is_active` | bool | Global account switch; effective immediately (§4.4) |
| `is_staff` | bool | Platform administrator (Django admin + `/platform/` API) |
| `is_superuser` | bool | |
| `date_joined`, `last_login` | datetime | |
| `password_changed_at` | datetime | Credential-invalidation reference point |

Base classes: `AbstractBaseUser` + `PermissionsMixin` (needed only for Django admin access by platform staff).

**Case-insensitive email ([ADR-0008](adr/0008-email-identity-normalization.md)):**

- `normalize_email()` (single helper in `accounts`) applies: strip whitespace, Unicode NFKC
  normalization, lowercase the full address. Applied in the manager, model `clean()`/`save()`, all
  serializers, authentication lookups, invitation creation, and password-reset requests.
- Database enforcement: `UniqueConstraint(Lower("email"), name="accounts_user_email_ci_uniq")`.
  This guarantees uniqueness even if some write path bypasses normalization.
- Lookups use the normalized value (`email=normalized`) so the functional index is used; no
  `iexact`/`ILIKE` scans on hot paths.
- **Uniqueness races:** creation runs inside `transaction.atomic()`; an `IntegrityError` on the
  constraint is caught inside a savepoint and mapped to a domain `EmailAlreadyRegisteredError`
  (HTTP 409 or a generic response where enumeration matters — e.g. invitation acceptance).
  Pre-checks are UX only; the constraint is the source of truth.
- `Invitation.email` uses the same normalization and a partial functional unique constraint
  (`Lower("email"), organization` where pending).
- Rejected alternative: PostgreSQL nondeterministic ICU collation — it works in Django 5.2 but
  breaks `LIKE`-based lookups (`icontains`, `startswith`) on PostgreSQL < 18 and complicates admin
  search; the functional constraint is simpler and portable across supported PostgreSQL versions.

### 4.2 Tokens, sessions, rotation, and replay detection

Design ([ADR-0004](adr/0004-authentication-and-session-management.md)):

- **Access token**: JWT, 10-minute lifetime, HS256 with a dedicated `JWT_SIGNING_KEY`, claims:
  `sub` (user id), `sid` (session id), `jti`, `iat`, `exp`, `type=access`. Returned in the JSON
  body. **The frontend keeps it in memory only — never `localStorage` or `sessionStorage`** (also
  documented as a frontend requirement for the later frontend phase).
- **Refresh token**: opaque-to-client JWT, 7-day lifetime (absolute session cap 30 days), in an
  `HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth/` cookie. Never returned in a body.
- **Server-side session (token family)** — `accounts.AuthSession`:
  `id` (= `sid`), `user`, `current_refresh_jti` (stored hashed), `created_at`, `last_rotated_at`,
  `expires_at`, `revoked_at`, `revoke_reason`, `created_ip`, `user_agent`.
- **Atomic rotation** (`POST /auth/token/refresh/`):
  1. Validate signature, type, expiry of the presented refresh token.
  2. `SELECT … FOR UPDATE` the `AuthSession` row by `sid`.
  3. If the session is revoked/expired, or the user is inactive → 401.
  4. If `hash(jti) == current_refresh_jti` → issue new access + refresh tokens, store the new
     hashed `jti`, commit. Only one concurrent request can win this compare-and-swap.
  5. If `jti` does not match (an already-rotated token was replayed) → **reuse detected**: revoke
     the whole session (family), commit, record `auth.refresh_reuse_detected` audit event, return 401.
  - **Replay revocation must commit even though the response is an authentication error.** The
    rotation service never raises inside its `transaction.atomic()` block on the replay path:
    it revokes the session, writes the security audit event, lets the block commit, and *returns*
    a `REUSE_DETECTED` outcome. The view converts that outcome into the 401 response after the
    transaction has committed. Raising an exception inside the atomic block (or enabling
    `ATOMIC_REQUESTS`) would roll the revocation back and leave the stolen token family usable.
    A `transaction=True` regression test asserts that, after the 401, the session row is revoked
    in the database and the audit event exists.
  - Trade-off: two concurrent refreshes with the same token cause the loser to be treated as reuse
    and the session to be revoked. This is the secure default (ADR-0004).
  - **Frontend requirement — coordination across tabs, not only within a tab.** All tabs of the
    same browser share one refresh cookie, so per-tab single-flight is insufficient. The frontend
    must serialize refreshes across tabs with the Web Locks API (`navigator.locks.request` on a
    single named lock), re-check after acquiring the lock whether another tab has already
    refreshed (shared via `BroadcastChannel`), and only then call the refresh endpoint. Because the
    browser updates the shared cookie after each rotation, the next tab to acquire the lock sends
    the new refresh token. A fallback for browsers without Web Locks (e.g. a `localStorage`-event
    based mutex that stores no tokens) must be designed in the frontend phase. Access tokens
    remain in memory per tab and are never written to `localStorage`/`sessionStorage`; if tokens
    are shared via `BroadcastChannel`, they stay in memory only. Any server-side grace window for
    concurrent refreshes would weaken replay detection and requires a separate ADR.
- **Access-token validation on every request**: signature/expiry, then one query joining
  `AuthSession` + `User`; reject if session revoked/expired or user inactive. This makes logout,
  password change, deactivation, and reuse revocation effective **immediately** for access tokens,
  not after expiry. Cost: one indexed lookup per request (the user is loaded anyway).
- **Logout**: revokes the current session and clears the cookie.

### 4.3 CSRF protection on cookie-authenticated endpoints

- Cookie-authenticated endpoints: `/auth/token/refresh/` and `/auth/logout/` (logout also
  accepts the cookie). Bearer-authenticated endpoints are not CSRF-susceptible because browsers
  never attach the `Authorization` header automatically.
- Enforcement: Django `CsrfViewMiddleware` semantics applied explicitly on these views
  (`csrf_protect`), double-submit pattern (`csrftoken` cookie readable by the SPA + `X-CSRFToken`
  header), strict `Origin`/`Referer` checking against `CSRF_TRUSTED_ORIGINS`, plus
  `SameSite=Strict` on the refresh cookie as defence in depth.
- `GET /auth/csrf/` issues the CSRF cookie.
- Tests use `APIClient(enforce_csrf_checks=True)`: missing token, wrong token, foreign origin → 403.

### 4.4 Credential invalidation and deactivation

- **Password change** (authenticated, requires current password) and **password reset confirm**:
  in one transaction set the new password, set `password_changed_at=now()`, revoke **all**
  `AuthSession`s of the user (all refresh tokens and, via §4.2 per-request check, all access
  tokens). Password change then issues a fresh session for the caller.
- Belt-and-braces: tokens with `iat < password_changed_at` are rejected even if a session were
  somehow left active.
- **Deactivation** (`is_active=False`, by platform staff): revokes all sessions in the same
  transaction; per-request checks reject the user immediately. Deactivation is blocked if the user
  is the last active Owner of **any** active organization, including when the user belongs to
  several organizations; the error lists every blocking organization so ownership can be
  transferred first. Locking and ordering rules are in §6.3.
- Membership suspension/removal takes effect immediately because membership is resolved per request.

### 4.5 Authentication abuse protection

DRF's built-in throttles (cache read-modify-write, not atomic) are kept only as a coarse outer
layer. The primary control is an **atomic, database-backed limiter** (`accounts.AuthRateLimit`):

- Counters keyed by `(scope, key_digest, window_start)`, where `key_digest` is an HMAC-SHA256 of
  the IP or normalized email (no raw identifiers stored).
- Incremented with a single statement:
  `INSERT … ON CONFLICT (scope, key_digest, window_start) DO UPDATE SET count = count + 1 RETURNING count`
  — atomic under concurrency, no lost updates.
- Scopes: login per IP, login per account, login per IP+account, password-reset per IP and per
  account, invitation-accept per IP, refresh per IP.
- **Per-account failure backoff**: after N consecutive failures, further attempts for that
  account are rejected for an exponentially increasing period (capped, e.g. 15 min). Temporary,
  not permanent, to avoid turning lockout into a denial-of-service against victims. Reset on success.
- Constant-ish response: identical error and comparable timing for unknown email vs wrong password
  (Django's backend runs the hasher for unknown users).
- Expired counter rows are purged by a management command (`purge_auth_rate_limits`).
- `REMOTE_ADDR` is used by default; `X-Forwarded-For` is honoured only when a trusted proxy count
  is explicitly configured, to prevent IP spoofing.

### 4.6 Invitation acceptance

- Tokens: 256-bit random, delivered by email only, stored as SHA-256 hash, expire (default 7 days),
  single use, revocable.
- `GET /invitations/{token}/` — preview (organization name, masked email, whether an account exists
  is **not** revealed beyond what the token holder can already infer).
- `POST /invitations/{token}/accept/`:
  - **If an account with the invited email exists: the caller must be authenticated as that user**
    (bearer token) and the authenticated user's normalized email must equal the invitation email.
    An unauthenticated request receives a response instructing sign-in; no password is accepted
    on this endpoint for existing accounts.
  - If no account exists: the caller supplies `full_name` and `password` (validated); the account
    is created with the invitation email (email ownership is proven by token possession).
  - Membership creation, role assignment, invitation consumption (row locked with
    `SELECT … FOR UPDATE` to prevent double acceptance), and audit event are one transaction.

### 4.7 Explicitly out of scope

MFA, SSO/SAML/OIDC, social login, self-service registration and organization signup. The session
model and audit events are designed so these can be added later without schema rewrites.

---

## 5. Multi-organization membership and tenant isolation

### 5.1 Strategy

Shared database, shared schema, every tenant-owned row carries a non-null `organization_id`.
Rationale and alternatives in [ADR-0003](adr/0003-tenant-isolation.md). Users are global; their
relationship to an organization (status, roles) lives on `Membership`.

### 5.2 Enforcement layers

1. **Tenant in the URL path** — `/api/v1/organizations/{org_id}/…`. Never in a header or body.
2. **Never trust a body-supplied organization** — serializers for tenant resources do not expose a
   writable `organization` field; services receive the organization only from the resolved
   request context. A test asserts that supplying `organization`/`organization_id` in a body is
   ignored or rejected.
3. **Central resolution** — `OrganizationScopedViewMixin` resolves the organization and the caller's
   *active* membership in an *active* organization (and active user). Missing → **404** (no
   existence disclosure). Sets `request.organization`, `request.membership`.
4. **Membership + permission on every tenant endpoint** — `HasOrgPermission` with per-action
   `required_permissions`; **default deny** if an action declares none.
5. **Scoped querysets** — `TenantScopedModel` + `TenantQuerySet.for_organization(org)`; scoped
   views obtain querysets only via `get_scoped_queryset()`.
6. **Nested identifiers** — every child lookup filters by both `id` and `organization`
   (and the parent where applicable). An ID from organization A under organization B's URL → 404.
   Related-object references in request bodies (e.g. role IDs when assigning roles) are validated
   to belong to the same organization.
7. **Mandatory tests** — the tenant-isolation matrix and route-coverage meta-test (§10) run in CI on
   every pull request; a new tenant endpoint cannot be merged without being covered.

### 5.3 Models

- **`organizations.Organization`** — `id`, `name`, `slug` (unique), `organization_type`
  (`school`/`university`/`training`/`other`), `status` (`provisioning`/`active`/`suspended`), `timezone`
  (IANA), `created_at`, `updated_at`, `created_by`.
- **`organizations.Membership`** (tenant-scoped) — `id`, `organization`, `user`, `status`
  (`active`/`suspended`), `joined_at`, `roles` (through `MembershipRole`).
  `UniqueConstraint(organization, user)`.
- **`organizations.MembershipRole`** — `membership`, `role`, `assigned_by`, `assigned_at`;
  constraint that `role.organization == membership.organization` enforced in the service and
  checked by tests.
- **`organizations.Invitation`** (tenant-scoped) — `id`, `organization`, `email`, `roles`,
  `token_hash`, `invited_by`, `expires_at`, `accepted_at`, `accepted_by`, `revoked_at`.

Organizations are created by platform administrators only (D2). Creation seeds system roles and
invites the initial Owner, atomically.

**Provisioning lifecycle.** Because the initial Owner exists only after accepting an invitation,
an organization is never created `active`. `status` has three values:

| Status | Meaning | Tenant API |
|---|---|---|
| `provisioning` | Created by a platform administrator; initial Owner invitation pending | Closed: every tenant endpoint returns 404; only the invitation preview/accept flow can reach it |
| `active` | Has ≥ 1 active Owner; the ownership invariant (§6.3) applies | Open (membership + permission rules) |
| `suspended` | Disabled by a platform administrator | Closed |

- `provisioning → active` happens **only** inside the invitation-acceptance transaction for an
  invitation carrying the Owner role: lock the organization row, lock the invitation, create the
  Owner membership, set `active`, write audit events, commit. If any step fails, the organization
  stays `provisioning`.
- Platform administrators can revoke and reissue the initial Owner invitation while
  `provisioning`; there is no manual "activate" operation, so an active organization without an
  active Owner cannot be created.
- `suspended → active` reactivation re-checks that an active Owner exists, under the same lock.
- A database `CHECK` constraint cannot express "has an Owner"; the invariant is enforced by
  services under lock and covered by tests (including the provisioning flow).

### 5.4 Future RLS requirements (Phase 2 gate)

Before sensitive student, examination, or response records are introduced, a security review must
decide on RLS. If adopted, the implementation must satisfy (detailed in ADR-0003):

- Separate database roles: a migration/owner role and a runtime role without `BYPASSRLS`;
  `FORCE ROW LEVEL SECURITY` on tenant tables.
- Tenant context set per transaction with `SET LOCAL app.current_organization_id`, from the
  resolved membership only; transaction-scoped so pooled connections cannot leak context.
- Policies `USING (organization_id = current_setting('app.current_organization_id')::uuid)` and
  matching `WITH CHECK` on all tenant tables; fail closed when the setting is absent.
- Explicit, audited, narrowly-scoped bypass paths for cross-tenant operations ("my organizations",
  platform administration).
- RLS-specific tests proving cross-tenant reads/writes fail at the database level even when the
  application filter is removed.

Phase 1 prepares for this: app connects as a non-superuser role; all tenant data inherits
`TenantScopedModel`; tenant context is resolved in one place.

---

## 6. Organization-scoped customizable RBAC

### 6.1 Model

- **Permission catalog in code** (`rbac/registry.py`): each app registers permission codes; a
  `post_migrate` sync upserts `rbac.Permission` (`code`, `description`, `category`,
  `is_deprecated`). Phase 1 codes: `organization.view`, `organization.update`, `members.view`,
  `members.manage`, `invitations.manage`, `roles.view`, `roles.manage`, `audit.view`.
- **`rbac.Role`** (tenant-scoped) — `id`, `organization`, `name`, `description`, `is_system`,
  `system_key` (`owner`/`admin`/`member`/null), `permissions` (M2M), timestamps.
  `UniqueConstraint(organization, Lower("name"))`; `UniqueConstraint(organization, system_key)`
  where not null.
- **System roles** seeded per organization: **Owner** (implicitly *all* catalog permissions,
  evaluated dynamically so new permissions are included; not editable or deletable), **Admin** and
  **Member** (editable defaults). Custom roles: create/rename/delete, any catalog permissions.

### 6.2 Evaluation

Effective permissions = union across the membership's roles (Owner ⇒ all), computed once per
request with one query and cached on the request. `HasOrgPermission` checks per-action
requirements; default deny.

### 6.3 Ownership invariant

> Every **active** organization has at least one **active Owner**: an active membership holding the
> Owner role, belonging to an active user.

Operations that can break it — removing a membership, suspending a membership, removing the Owner
role from a membership, deactivating a user, accepting a role change — go through services that:

1. Open `transaction.atomic()`.
2. `SELECT … FOR UPDATE` the **organization row** (serializes all ownership-affecting operations for
   that organization; prevents write-skew where two concurrent requests each demote a different
   Owner under READ COMMITTED).
3. Lock the target membership row.
4. Count remaining active Owners excluding the target; if zero → `LastOwnerError` (HTTP 409).
5. Apply the change and write the audit event in the same transaction.

Applies only to `active` organizations; `provisioning` organizations are governed by the
lifecycle in §5.3.

**Global account deactivation** (one user, possibly Owner in many organizations), in one
transaction:

1. Lock the user row (`SELECT … FOR UPDATE`) so two deactivations of the same user serialize.
2. Find every `active` organization where the user holds an active Owner membership and lock
   those organization rows **in ascending id order** (deterministic order prevents deadlocks with
   other multi-organization operations).
3. For each locked organization, count active Owners **other than this user** whose membership is
   active *and* whose user account is active.
4. If any organization would be left with zero, abort with `LastOwnerError` listing all blocking
   organizations; nothing is changed.
5. Otherwise set `is_active=False`, revoke all sessions, write audit events, commit.

Because every operation that can reduce an organization's active-Owner set — membership removal or
suspension, Owner role removal, and account deactivation — locks the affected organization rows
first, two co-Owners deactivated concurrently cannot both succeed: the second transaction waits
for the first and then sees the committed deactivation. Concurrency regression tests cover
co-Owners across two organizations deactivated simultaneously.

### 6.4 Escalation and Owner-level rules

- **No self-promotion**: a user cannot change their own role assignments or their own membership
  status (an Owner may remove their *own* Owner role only if another active Owner remains).
- **No escalation**: granting permissions to a role, or assigning a role to a member, requires the
  actor to hold every permission involved.
- **Owner role assignment/removal** is restricted to Owners.
- **Owner role immutability**: cannot be edited, deleted, or have its permissions changed.
- **Owners are not exempt**: Owner actions go through the same services and invariant checks; no
  code path short-circuits on "is owner".
- **Platform administrators** use separate `/platform/` endpoints that call the same services —
  they cannot bypass invariants either, and they do not get implicit tenant access through the
  tenant API.
- **Concurrent changes to the actor's own permissions.** Permissions computed at the start of a
  request can be stale by the time a sensitive mutation commits (e.g. the actor's role is
  removed, or their role loses `roles.manage`, by a concurrent request). Every authorization-
  sensitive mutation (role create/update/delete, role permission changes, member role assignment,
  membership status changes, invitations granting roles) therefore:
  1. takes the organization row lock (§6.3) — all RBAC mutations for an organization serialize on it;
  2. **re-loads the actor's membership and effective permissions inside the locked transaction**
     and re-checks the required permission and the escalation rules against that fresh state,
     rejecting with 403 if they no longer hold;
  3. only then applies the change.
  The request-level permission check remains as a fast early rejection; the in-transaction check
  is authoritative. Regression tests race an actor's mutation against the concurrent removal of
  that actor's permission and assert that the mutation is rejected or ordered strictly before
  the removal — never applied with revoked authority.

### 6.5 Tests

Unit tests for every rule; integration tests via the API; **concurrency regression tests**
(`transaction=True`, threads synchronized with a barrier) proving that two simultaneous demotions/
removals of the last two Owners leave exactly one Owner and one `LastOwnerError`; an authorization
matrix for each role × endpoint.

Rejected alternatives: Django `Group`/`Permission` (global, not per tenant), django-guardian
(object-level, unnecessary granularity). Future scope-level roles (per course/exam) can be added
via a nullable scope on `MembershipRole` ([ADR-0005](adr/0005-rbac-and-ownership-invariants.md)).

---

## 7. Audit logging

`audit.AuditLog` ([ADR-0006](adr/0006-audit-logging.md)):

| Field | Notes |
|---|---|
| `id` | UUID |
| `organization` | nullable (platform/auth events) |
| `actor`, `actor_email` | actor nullable for anonymous events; email snapshot |
| `action` | dotted code, e.g. `member.roles_changed` |
| `outcome` | `success` / `failure` |
| `target_type`, `target_id` | |
| `changes` | JSONB, allowlisted fields only |
| `metadata` | JSONB, redacted |
| `ip_address`, `user_agent`, `request_id` | |
| `created_at` | indexed with `(organization, created_at)` |

Rules:

- **Atomic with mutations**: `audit.record()` is called inside the same `transaction.atomic()` as
  the mutation. Rollback of the mutation rolls back the event; there is never a committed mutation
  without its event.
- **Failed authentication events are separate**: failures (bad password, rate-limited, bad token,
  refresh reuse) are not part of a successful transaction. They are recorded by
  `audit.record_security_event()` in their own short transaction, *after* any failed business
  transaction has rolled back, so they are never lost to a rollback and never imply a change
  happened. The project does not use `ATOMIC_REQUESTS`, so request-level rollback cannot discard them.
- **Append-only, twice**: model `save()` refuses updates, `delete()` and queryset
  `update()/delete()` raise; a PostgreSQL `BEFORE UPDATE OR DELETE` trigger raises an exception.
  Runtime DB role is granted `INSERT, SELECT` only on the table (dev/CI init scripts).
- **No secrets**: passwords, password hashes, access/refresh tokens, invitation and reset tokens
  (raw or hashed), JWT signing material, and CSRF tokens are never written. Enforced by a central
  redaction allowlist and a test that scans every recorded event in the suite for known secret values.
- **Read API**: `GET /organizations/{id}/audit-logs/` (`audit.view`), filters by action/actor/date/
  outcome, cursor pagination. Platform/auth events visible only to platform administrators.

---

## 8. API security controls

| Control | Implementation |
|---|---|
| Default authentication | `IsAuthenticated` default; public endpoints explicitly allowlisted and verified by test |
| Tenant authorization | membership resolution + `HasOrgPermission`, default deny |
| Enumeration resistance | 404 for foreign tenants/resources; identical login failures; password reset always 202 |
| Abuse | atomic DB limiter + backoff (§4.5); DRF throttles as outer layer |
| Passwords | Argon2id; validators: min length 12, common-password, user-attribute similarity, numeric |
| Tokens | §4.2–4.4 |
| CSRF / CORS | §4.3; explicit origin allowlist |
| Transport/headers (prod) | SSL redirect, HSTS (preload-ready), secure cookies, `X-Frame-Options: DENY`, nosniff, strict referrer policy, COOP |
| Secrets | environment only; production refuses insecure/missing `DJANGO_SECRET_KEY` or `DEBUG=True` |
| Input | serializers validate all input; page size cap; request body size limit |
| Database | non-superuser runtime role; least-privilege grants |
| Supply chain | pip-audit, bandit, ruff security rules, Dependabot, SHA-pinned actions, detect-secrets pre-commit |

---

## 9. API conventions

### 9.1 Endpoints (`/api/v1`)

Auth & self: `POST /auth/login/`, `POST /auth/token/refresh/` (cookie + CSRF),
`POST /auth/logout/` (cookie + CSRF), `GET /auth/csrf/`, `GET|PATCH /auth/me/`,
`POST /auth/password/change/`, `POST /auth/password/reset/`, `POST /auth/password/reset/confirm/`,
`GET /invitations/{token}/`, `POST /invitations/{token}/accept/`.

Tenant (`/organizations/{org_id}/…`): `GET /organizations/` (caller's memberships),
`GET|PATCH /organizations/{org_id}/`, `GET /organizations/{org_id}/me/` (own roles + effective
permissions), `members/` (list, retrieve, PATCH status, DELETE), `members/{id}/roles/` (PUT),
`invitations/` (list, create, `{id}/revoke/`), `roles/` (CRUD), `permissions/` (catalog),
`audit-logs/`.

Platform (staff): `GET|POST /platform/organizations/`, `GET|PATCH /platform/organizations/{id}/`.

Operations: `GET /health/live/`, `GET /health/ready/`; docs: `/api/schema/`, `/api/docs/`, `/api/redoc/`.

### 9.2 Errors — RFC 9457 Problem Details ([ADR-0007](adr/0007-api-error-format.md))

`application/problem+json` with `type`, `title`, `status`, `detail`, stable `code`, optional
`errors` (field errors), and `request_id`. Unhandled exceptions → generic 500 with `request_id`
only; details go to logs.

### 9.3 Documentation and observability

drf-spectacular on every view including error responses; schema committed to
`docs/api/openapi.yaml` with CI drift detection; request-ID middleware; structured JSON logs.

---

## 10. Testing strategy

pytest + pytest-django + factory-boy + time-machine, **always against PostgreSQL** (17 in Docker/CI).
Coverage gate **90%** (branch coverage), target 100% for `accounts`, `organizations` (tenancy),
`rbac`, `audit`.

| Suite | Coverage |
|---|---|
| Unit | services, selectors, permission engine, email normalization, token/session logic, limiter |
| Integration | full HTTP flows with real middleware and DB |
| Security (`tests/security/`) | tenant-isolation matrix; route-coverage meta-test; escalation; auth attacks (tampered/`alg=none`/expired JWT, refresh replay, CSRF, post-password-change and post-deactivation token use); limiter atomicity; enumeration; data exposure; audit secret scan |
| Concurrency | last-Owner races; refresh rotation races; invitation double-accept; email uniqueness races |
| Migration | `makemigrations --check`; fresh `migrate`; audit trigger at SQL level |

---

## 11. Docker development environment

- `db`: `postgres:17-alpine`, healthcheck, named volume, init script creating the non-superuser
  runtime role `aems_app` and database `aems`.
- `backend`: Dockerfile `dev` target, source bind-mounted, virtualenv outside the mount, waits for
  a healthy `db`.
- `mailpit`: local SMTP sink with web UI (dev only).
- Dockerfile: `base` → `dev` → `prod` (non-root user, gunicorn, healthcheck). Built in CI, never deployed.
- `Makefile` for common tasks; `pre-commit` for ruff, formatting, hygiene, secret scanning, mypy.

---

## 12. CI (GitHub Actions) — Batch 2

- Triggers: `pull_request` and `push` to `main`, **without path filters**. Every pull request
  produces every check result, so required checks cannot be bypassed through path-filter
  omissions (the Batch 2 authorization preferred this over the broadened filters originally
  listed here). No `workflow_dispatch`, because CI is never triggered manually.
- As implemented: see [ADR-0011](adr/0011-continuous-integration.md) for the job and check names.
- Jobs: **lint** (ruff check/format, mypy), **test** (PostgreSQL 17 service, `uv sync --frozen`,
  `makemigrations --check --dry-run`, `migrate`, full pytest incl. security/isolation/concurrency
  suites, coverage ≥ 90%), **security** (pip-audit, bandit), **schema** (OpenAPI drift),
  **docker** (build `prod` target, no push).
- `permissions: contents: read` at workflow level; third-party actions pinned to full commit SHAs;
  `persist-credentials: false` on checkout; concurrency group cancels superseded runs; no secrets required.
- Dependabot for pip (uv), Docker, and GitHub Actions.
- Recommending CI as a required status check is a branch-protection change and is left to the
  repository owner.

---

## 13. Implementation batches

One pull request per batch, each with its own tests and documentation, stopping for review after each.

| # | Batch | Deliverables |
|---|---|---|
| 1 | Repository scaffolding | Monorepo layout, uv/pyproject, split settings, Docker Compose (db, backend, Mailpit), Dockerfile, Makefile, pre-commit, health endpoints, README/CONTRIBUTING, PR template |
| 2 | Core infrastructure & CI | Core base models, RFC 9457 handler, request-ID middleware, structlog, DRF + pagination, drf-spectacular, GitHub Actions, Dependabot |
| 3 | Accounts & authentication | Custom User (first auth migration), email normalization + CI constraint, Argon2, JWT + AuthSession rotation/replay detection, CSRF, auth endpoints, password change/reset, atomic abuse limiter, admin |
| 4 | Organizations & tenancy | Organization/Membership, TenantScopedModel, scoped view mixin, org + platform endpoints, isolation test harness |
| 5 | Audit logging | AuditLog, record/record_security_event, append-only trigger + grants, redaction, wire Batch 3–4 events, audit endpoint |
| 6 | RBAC | Registry + sync, Role/MembershipRole, seeding, engine, `HasOrgPermission`, role/member endpoints, ownership invariant with locking, escalation guards, concurrency tests |
| 7 | Invitations | Invitation model, hashed tokens, create/revoke/preview/accept (authenticated for existing users), emails, double-accept protection |
| 8 | Security hardening & review | Complete isolation matrix, route meta-test, auth attack suite, prod settings hardening, SECURITY.md, remaining ADRs, schema regeneration, Phase 1 report |

## 14. Out of scope for Phase 1

Examination/assessment/course/student domain models, frontend, MFA/SSO, self-service signup,
billing, Redis/Celery, file storage, RLS (gated for Phase 2), i18n, deployment, AI features.

---

## 15. Implementation progress

| Batch | Status | Pull request | Notes |
|---|---|---|---|
| 1 — Repository scaffolding | Merged | rahilashraf/aems-portfolio#1 | Review findings AEMS-001…006 resolved before merge |
| 2 — Core infrastructure & CI | Merged | rahilashraf/aems-portfolio#2 | Review findings AEMS-007…009 resolved before merge |
| 3 — Accounts & authentication | Merged | rahilashraf/aems-portfolio#4 | Review findings AEMS-010/011 and the password-reset outbox resolved before merge |
| 4 — Organizations & tenancy | Merged | rahilashraf/aems-portfolio#5 | Review findings AEMS-012…014 resolved before merge |
| 5 — Audit logging | Merged | rahilashraf/aems-portfolio#6 | Review findings AEMS-015/016 resolved before merge |
| 6 — RBAC | Merged | rahilashraf/aems-portfolio#7 | Review finding AEMS-017 resolved before merge |
| 7 — Invitations | Merged | rahilashraf/aems-portfolio#8 | Review finding AEMS-018 resolved before merge |
| 8 — Security hardening & review | Merged | rahilashraf/aems-portfolio#9 | Findings AEMS-019…028 and the admin sign-in audit-volume follow-up resolved; squash-merged as `3c3e0f20716c05f462a5228bb0e924690bbe13de`; six post-merge CI checks passed (run 45698594699) |

**Phase 1 Backend Foundation status:** Complete. All eight backend batches were merged and all six post-merge CI checks passed on `3c3e0f20716c05f462a5228bb0e924690bbe13de`. This does not include the separately planned frontend, deployment, or Phase 2 data models.

### Batch 2 deviations from the original plan

- **django-cors-headers moved from Batch 3 to Batch 2**, because the Batch 2 authorization asked for
  secure, environment-based CORS defaults. There are no origins by default, credentials are off,
  and production requires HTTPS origins.
- **djangorestframework-stubs 3.16.x with DRF 3.18.x.** Stub releases 3.17 and later require
  django-stubs 6.x (Django 6). The 3.16 line is the newest that works with Django 5.2 LTS. Runtime
  DRF stays on the latest release for security fixes.
- **Problem `type` is `about:blank`** with a stable `code` member (ADR-0009 refines ADR-0007),
  because AEMS has no owned, dereferenceable problem-type URI host yet.
- **No DRF versioning class.** Versioning is the `/api/v1/` URL prefix and the `api-v1` URL
  namespace, which is simpler and documented in the schema.
- **django-structlog not adopted** (ADR-0010). A first-party middleware keeps client-IP and
  path-logging policies explicit.
- **gunicorn access log disabled** in the production image, because it would log query strings.
- **Review corrections AEMS-007–009** (before merge):
  - layered allowlist enforcement with a runtime guard and five system checks (ADR-0012);
  - bounded, cycle-safe log redaction and text sanitization;
  - client-safe error message conventions (`DomainError`, ADR-0009).
- **API root endpoint (`GET /api/v1/`)** added as the only Batch 2 API endpoint. It is public, and
  it exercises the allowlist, schema and contract machinery.

### Batch 3 deviations and clarifications (ADR-0013)

- **Security events instead of audit rows.** The replay-detection "audit event" is emitted through
  the new `apps.core.security_events` interface (a structured log for now). Durable audit
  persistence stays in Batch 5, and no audit schema was added early.
- **DRF throttles not used.** The atomic PostgreSQL limiter (`AuthRateLimit`) plus account backoff
  (`AuthBackoff`) replace the planned coarse DRF throttle layer.
- **Login is not CSRF-checked.** It accepts only JSON, and cross-origin JSON requires a CORS
  preflight. CSRF is enforced on the cookie-authenticated refresh and logout operations.
- **Logout is a public (allowlisted) endpoint**, so an expired access token cannot prevent
  signing out.
- **Session-management endpoints added** (`GET /auth/sessions/`, `DELETE /auth/sessions/{id}/`,
  `POST /auth/sessions/revoke-others/`), as requested by the Batch 3 authorization.
- **Password-reset token in the URL fragment** (`#uid=…&token=…`), so it is never sent to servers or
  in Referer headers.
- **Review corrections AEMS-010 and AEMS-011** (ADR-0013): password-reset delivery failures keep the
  generic `202` and are reported as sanitized security events. Cookie logout resolves the session
  by the token's signed `sid` **and** `sub`.
- **Password-reset email outbox** (ADR-0014; approved scope extension). Requests enqueue into
  `PasswordResetOutbox` and never contact SMTP, which removes the mail-server timing side channel.
  The outbox stores no address, token or body: both are derived at send time. The
  `deliver_password_reset_emails` command delivers with `SKIP LOCKED` claims, leases, bounded
  retries and expiry. It must be scheduled externally; scheduling and deployment are deferred.
  This is not a general job queue (Redis/Celery stay out of scope).

### Batch 4 deviations and clarifications (ADR-0015)

- **No activation path.** `provisioning → active` (Batch 7 invitation acceptance) and
  `suspended → active` (Owner check, Batches 6/7) are rejected with 409. Platform administrators
  can only suspend active organizations. Tests use a documented test-only activation fixture.
- **Authorization before RBAC.** `HasOrgPermission` exists with per-action declarations and
  default deny. Membership authorizes only declared read-only actions, and permission evaluation
  returns False until Batch 6. `PATCH /organizations/{org_id}/` is therefore routed but answers
  403.
- **Platform administrators** must be active staff **and** hold the Django model permission for
  the method (`view`/`add`/`change_organization`). The plan said "staff"; the model permissions
  make platform authority explicit and scoped.
- **Bodies naming an organization are rejected** (400), rather than ignored.
- **`/organizations/{org_id}/me/`** returns the membership only. Roles and effective permissions
  are added in Batch 6.
- **The organization slug is immutable** after creation.
- **Admin** is read-only for organizations and memberships, so it cannot bypass the lifecycle.
- **Test-only tenant resource** `tests.fixtures_app.TenantNote` exercises nested lookups and
  writes in the isolation matrix before real tenant resources exist.
- **Deferred:** members, roles and permissions (Batch 6); invitations (Batch 7); audit logs
  (Batch 5); RLS (Phase 2).

### Batch 5 deviations and clarifications (ADR-0016)

- **Database role split.** Least privilege on the audit table is impossible while the runtime role
  owns every table, so the smallest split was introduced:
  - an owner role (migrations, tests) and a runtime role (the application);
  - grants applied after every `migrate`;
  - a `verify_runtime_privileges` command;
  - an upgrade script for existing databases.
- **`apps.core.security_events` is log-only.** Durable records are written by the audit service
  directly, not by a sink. Mutation records are inside their transactions; independent events use
  `transaction.atomic(durable=True)`.
- **`auth.refresh.rotated` and `auth.logout` are log-only events.** Rotation is high volume and
  changes no account state. A logout that revokes a session is recorded durably as
  `auth.session.revoked` in the revocation's transaction; a separate durable `auth.logout` row
  would duplicate it and, written after the revocation committed, could turn a completed logout
  into a 500 (review finding AEMS-016).
- **Self-service profile changes** (`PATCH /auth/me/`) go through `accounts.services.update_profile`
  and record `auth.account.profile_updated` in the same transaction; unchanged submissions record
  nothing (review finding AEMS-015).
  Session creation is recorded by `auth.login.succeeded`. Undecodable refresh tokens are now
  recorded as `auth.refresh.rejected`.
- **New admin events:** account creation, privileged-field and permission changes, and the
  administrator as actor for admin password changes and session revocations.
- **`tenant.access_denied`** belongs to no organization (it may name an organization the caller
  cannot see).
- **New platform route** `GET /platform/audit-logs/`, for events without an organization, requiring
  `audit.view_auditlog`. The tenant route requires `audit.view` and fails closed until Batch 6.
- **No `TRUNCATE` trigger:** `TRUNCATE` is denied to the runtime role by privileges. The owner
  keeps it because test-database flushing uses it.
- **Saving an audit row twice** raises; `bulk_create` is disabled for audit rows.
- **Deferred:** retention, archival, hash chaining; database-level protection against the owner
  or superusers.

### Batch 6 deviations and clarifications (ADR-0017)

- **`MembershipRole` lives in `apps.rbac`** (§5.3 placed it in `organizations`). Composite foreign
  keys on `(id, organization_id)` make a cross-tenant assignment impossible even with raw SQL.
- **Permission rows are protected in the database:** codes are immutable and rows cannot be
  deleted; retired codes are deprecated and grant nothing.
- **`GET /organizations/{org_id}/` requires `organization.view`** (review finding AEMS-017), which
  the default Member role holds. `me/` stays available to every active member.
- The deviations below were approved in the Batch 6 review.
- **Delegation is broader than §6.4:**
  - suspending, reactivating or removing a member requires holding every permission the member's
    roles confer;
  - only Owners can change an Owner's membership.
- **Assigned custom roles cannot be deleted** (`409 role_in_use`), rather than being silently
  removed from members.
- **Global deactivation locks every organization in which the user has a membership** (ascending
  id), not only those where the user is an Owner. This closes a window in which the user becomes
  Owner elsewhere. Global lock order: user → organizations → memberships → roles.
- **Existing organizations** receive the system role definitions by migration. No membership is
  given a role, and no organization changes status.
- **Not added in Batch 6:**
  - platform RBAC endpoints;
  - `suspended → active` reactivation (still rejected);
  - self-service leaving of an organization.
- **Batch 7 must:**
  - lock the accepting user row before the organization row;
  - apply the delegation rules to roles carried by invitations;
  - assign the initial Owner and activate the organization in one transaction.

### Batch 7 deviations and clarifications (ADR-0018)

- **Tokens are issued when the email is sent** by `deliver_invitation_emails`, not at creation.
  Only the SHA-256 digest is stored, and every send rotates the token, so only the latest email's
  link works.
- **Initial Owner invitation.** `POST /platform/organizations/` requires `initial_owner_email`.
  Platform administrators reissue or revoke it through
  `/platform/organizations/{id}/initial-owner-invitation/` with the new
  `organizations.manage_initial_owner_invitation` permission. This also covers organizations
  created before Batch 7.
- **Preview and acceptance are non-enumerating:**
  - every unusable token gets the same 404 `invitation_invalid`;
  - the preview never reveals whether an account exists;
  - acceptance tells the token holder to sign in when one does (§4.6).
- **Acceptance re-validates the inviter's authority** under the organization lock and fails closed
  (409 `invitation_authority_revoked`). The invitation stays pending for managers to revoke and
  reissue.
- **One pending invitation per address** (409 `invitation_already_pending` until revoked).
  Expired pending invitations are marked `expired` when replaced.
- **No session is issued on acceptance**; the new member signs in normally.
- **Lock order:** user row → organization row → invitation row → new membership and role rows. A
  new account's row is inserted first. Delivery never holds an organization lock.
- **Production requires an `https://` frontend origin** for emailed links.
- **Address ownership is re-checked under the user lock** (review finding AEMS-018): an email
  change committed while an acceptance waits is rejected.
- **Historical `InvitationRole` links** of finished invitations are removed when their custom
  role is later deleted (the role ids remain in the audit log). Documented; open for a decision.
- **`suspended → active` reactivation is still unavailable**, despite §5.3 (later restrictions
  forbid new activation paths). Flagged for review.
- **Deferred:** resending an email without reissuing, retention of old invitations and outbox
  rows, reactivation.

### Batch 8 security hardening and review (ADR-0019)

- **Structured review** of every Phase 1 area, with adversarial tests on real PostgreSQL (HTTP,
  raw SQL as the runtime role, synchronized threads). An independent read-only review ran in
  parallel; every reported issue was reproduced or verified against the code before being fixed.
- **Fixed findings** (details and regression tests in ADR-0019):
  - AEMS-021 (high): admin privilege escalation by non-superuser staff; deletions in the admin.
  - AEMS-027: deadlocks between ownership operations (user/organization locks are now
    `FOR NO KEY UPDATE`).
  - AEMS-023: unsafe production email backends.
  - AEMS-024: unbounded outbox re-delivery after crashed runs.
  - AEMS-025: unbounded audit growth from refused anonymous requests.
  - AEMS-019 / AEMS-020: 500s for oversized or deeply nested bodies and tampered audit cursors.
  - AEMS-022: unaudited admin email changes.
  - AEMS-026: insecure production CSRF trusted origins.
  - AEMS-028: database-deprecated codes still granted to Owners.
- **Security suites** in `backend/tests/security/` (§10): route policy, tenant-isolation matrix,
  authentication, password reset, invitations, RBAC/Owner concurrency, audit integrity, database
  safeguards, rate limiting, input validation, production settings, admin, outboxes.
- **Documentation:** [`SECURITY.md`](../SECURITY.md) (reporting, security model, production
  requirements, email authentication, outbox operation, retention, limitations) and the
  [Phase 1 final report](phase-1-final-report.md).
- **No new features or dependencies.** The production configuration gained two checks (CSRF
  trusted origins, email backend) and one opt-in (`AEMS_EMAIL_ALLOW_UNENCRYPTED_SMTP`, used by the
  CI container's Mailpit). The deploy check now sets an `smtp+tls://` URL and an HTTPS trusted
  origin.
- **Deferred (unchanged):** RLS (Phase 2 prerequisite), retention and archival, reactivation,
  platform RBAC, historical role snapshots, MFA/SSO.
