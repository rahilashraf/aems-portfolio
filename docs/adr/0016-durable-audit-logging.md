# ADR-0016: Durable audit logging (Batch 5)

- **Status:** Accepted
- **Date:** 2026-11-23
- **Implements:** [ADR-0006](0006-audit-logging.md); completes the security-event boundary of
  [ADR-0013](0013-authentication-implementation-and-security-events.md) and
  [ADR-0015](0015-organizations-and-tenancy-implementation.md)

## Context

Batches 3 and 4 reported security events through `apps.core.security_events`. Mutation events
were written to the structured log *after* commit, and failure events immediately. A log line
emitted after commit is not an audit record: it can be lost, and nothing guarantees it exists for
every committed change. Batch 5 adds durable, append-only audit records, without request-level
transactions (`ATOMIC_REQUESTS` stays off).

## Decisions

### Model (`apps.audit`, migrations `audit.0001_initial`, `audit.0002_append_only_trigger`)
`AuditLog` fields:
- `id` (UUID);
- `organization` and `actor`: nullable, `PROTECT`;
- `actor_email`: a snapshot from the user row, never from client input;
- `action`: dotted, enforced by `audit_auditlog_action_format`;
- `outcome`: `success` or `failure`, enforced by `audit_auditlog_outcome_valid`;
- `target_type` and `target_id`;
- `changes` and `metadata` (JSONB);
- `ip_address`, `user_agent` (sanitized, at most 256 characters) and `request_id`;
- `created_at`.

Indexes: `audit_org_created_idx (organization, created_at)`,
`audit_action_created_idx (action, created_at)` and `audit_actor_created_idx (actor, created_at)`.
No separate single-column foreign-key indexes, because the composite indexes lead with those
columns.

`AuditLog` is **not** a `TenantScopedModel`, because platform and account events have no
organization. Its queryset provides two scoped reads:
- `for_organization(org)` fails closed without a saved organization;
- `platform_events()` returns only rows without an organization.

The tenant API view uses the standard `OrganizationScopedViewMixin`, whose `get_scoped_queryset()`
calls `for_organization`.

### Append-only, in layers
1. **Model:** `save()` of an existing row, `save(update_fields=…)`, `force_update` and `delete()`
   raise `AuditLogImmutableError`.
2. **Queryset:** `update()`, `delete()`, `bulk_update()` and `bulk_create()` (including conflict
   updates) raise.
3. **PostgreSQL trigger** `audit_auditlog_append_only`: `BEFORE UPDATE OR DELETE FOR EACH ROW`
   raises for any role, including raw SQL. Reversing the migration drops it.
4. **Privileges:** the runtime role has only `SELECT, INSERT` on the table. `UPDATE`, `DELETE`,
   `TRUNCATE`, `REFERENCES` and `TRIGGER` are revoked from it and from `PUBLIC`.
5. **Admin:** read-only. It requires `audit.view_auditlog` and has no add, change, delete or bulk
   actions.

**Limits.** The table owner or a superuser can disable or drop the trigger and rewrite rows.
`TRUNCATE` bypasses row triggers, so only privileges stop it, and the owner keeps it (test-database
flushing relies on that). Protecting history from database administrators needs operational
controls: restricted owner credentials, backups and log shipping. Hash chaining and
retention/archival are deferred.

### Database roles (the smallest split that makes the privileges real)
Before Batch 5 one role owned every table and served requests. An owner can always disable
triggers and re-grant itself privileges, so least privilege needs two roles:

| Role | Owns | Used for | Notes |
|---|---|---|---|
| owner (`aems_owner`) | database, schema, tables | `migrate`, test suite, drift checks | `CREATEDB` in dev/CI only (pytest) |
| runtime (`aems_app`) | nothing | the application (`DATABASE_URL`) | `NOCREATEDB`; audit table `SELECT, INSERT` only |

- After every `migrate`, a `post_migrate` handler (`apps.audit.privileges`) grants the runtime
  role named by `DJANGO_DB_RUNTIME_ROLE`: `CONNECT`, schema `USAGE`, CRUD on all tables, sequence
  usage, then revokes the forbidden audit privileges.
- This works the same on fresh, test and upgraded databases. It refuses to run when migrations are
  executed as the runtime role, and refuses an unknown role.
- `manage.py verify_runtime_privileges` checks the connected role. It must not be a superuser or
  bypass RLS, must not own the audit table, must have `SELECT`/`INSERT`, must not have
  `UPDATE`/`DELETE`/`TRUNCATE`, and the trigger must be enabled. CI runs it as the runtime role.
- **New databases:** `docker/postgres/init/01-create-app-role.sh` creates both roles.
- **Existing databases:** `docker/postgres/upgrade/batch-5-role-split.sql`, run as a superuser,
  reassigns ownership. Then run `migrate` as the owner.
- **Production** must provision the same split; deployment remains deferred.

### Writing records: three lifecycles
| Kind | API | Transaction | When it exists |
|---|---|---|---|
| Mutation event | `audit.record(...)` | the caller's business transaction (required) | iff the mutation commits |
| Independent security event | `audit.record_security_event(...)` | its own: `transaction.atomic(durable=True)` | always, after the failed operation |
| Operational log | `apps.core.security_events` | none | log line only (after commit for mutations) |

- **`record()` requires an open transaction.** It raises `AuditTransactionError` otherwise, so a
  mutation cannot commit without its event by accident. A failure inserting the audit row
  propagates, so the mutation rolls back. A rollback discards both. The log line is emitted
  through `transaction.on_commit`, only after commit.
- **`record_security_event()` refuses nesting.** Because it uses `durable=True`, Django raises
  `RuntimeError` if it is called inside any enclosing transaction, including one marked for
  rollback. Callers record these events after their business transaction has ended. Nothing
  pretends a nested savepoint is independent.
- **The log layer is an observer, not a store.** Sink failures are caught and reported as
  `security.sink_failed`, so they cannot turn a committed mutation into an HTTP error. There is no
  persistence sink, so no event is written twice.

**How the former `record_after_commit` calls became atomic.** Each was replaced by `audit.record`
**inside** the transaction that performs the change:
- login and session creation;
- password change and reset completion;
- session revocation, single or bulk;
- deactivation;
- outbox status changes: the compare-and-set update and its record now share one transaction;
- organization creation, update, status change and profile update, under the organization row
  lock;
- admin account changes, inside the admin's transaction.

Refresh replay writes `auth.refresh.reuse_detected` inside the revocation transaction. That block
never raises, so the revocation and its record commit together before the view returns 401. If
the audit insert fails, neither commits.

### Events
Durable, transactional:
- `auth.login.succeeded`;
- `auth.password.changed`, `auth.password.changed_by_admin`;
- `auth.password_reset.requested`, `auth.password_reset.completed`;
- `auth.session.revoked`, `auth.sessions.revoked`, `auth.refresh.reuse_detected`;
- `auth.account.created`, `auth.account.updated`, `auth.account.permissions_changed`,
  `auth.account.deactivated`, `auth.account.profile_updated`;
- `auth.password_reset.email_delivered`, `delivery_failed`, `delivery_expired`,
  `delivery_cancelled`;
- `organization.created`, `organization.updated`, `organization.status_changed`,
  `organization.profile_updated`.

Durable, independent:
- `auth.login.failed`, `auth.login.locked`, `auth.rate_limited`, `auth.csrf.failed`;
- `auth.refresh.rejected` (with a `reason`), `auth.session.owner_mismatch`;
- `auth.password_change.failed`, `auth.password_reset.failed`,
  `auth.password_reset.enqueue_failed`, `auth.password_reset.delivery_lease_lost`;
- `auth.admin_login.failed`, `auth.admin_login.rate_limited`, `auth.admin_login.succeeded`;
- `tenant.access_denied`.

Log only:
- `auth.refresh.rotated`. It happens every few minutes per session and changes no account state;
  session creation is covered by `auth.login.succeeded`.
- `auth.logout`. The mutation a logout performs is recorded as `auth.session.revoked` inside the
  revocation transaction, and a logout that revokes nothing changes no state.

### Failure policy for mutations recorded in their own transaction (review findings)
- **Profile changes (AEMS-015).** `PATCH /auth/me/` calls `accounts.services.update_profile`. It
  locks the user row, applies only the allowlisted profile fields (`full_name`) and records
  `auth.account.profile_updated` (actor and target: the user; `changes` with `from`/`to`) in the
  same transaction. A submission that changes nothing writes nothing and records nothing. If the
  audit insert fails, the change rolls back and the request fails; the response body is unchanged
  otherwise.
- **Logout (AEMS-016).** Previously the revocation committed and then a separate durable
  `auth.logout` row was inserted; if that insert failed, a completed logout returned 500.
  Now:
  - an actual revocation and its `auth.session.revoked` record commit together, or neither does;
    if the mandatory record cannot be written, nothing is revoked, the cookie is not cleared and
    the request fails (no 204 for a revocation that did not happen);
  - nothing durable is written after that commit; `auth.logout` is an observational log line and
    log sinks never raise;
  - events recorded *before* any mutation (`auth.csrf.failed`, `auth.refresh.rejected`,
    `auth.session.owner_mismatch`) are unchanged: if they cannot be written the request fails with
    nothing committed.

### Organization association policy
- **Organization events** (`organization.*`) carry the organization and form its tenant history.
  This includes changes made by platform administrators, and the actor's id and email are visible
  to that organization's auditors.
- **Account, authentication and session events** have no organization. Users are global.
- **`tenant.access_denied`** has no organization; the requested id goes in `target_id`. The
  caller is not a member and the organization may not exist, so the event is platform data and
  never enters another tenant's history.

### Redaction (`apps.audit.redaction`)
- **Metadata:** keys must be allowlisted, each with a typed validator: UUIDs, SHA-256 digests,
  identifiers, bounded integers, booleans and bounded sanitized text. Unknown keys raise
  `AuditDataError`, so caller dictionaries are never copied wholesale. Keys that look sensitive
  are rejected unless explicitly allowlisted as identifier-only (`session_id`, `token_user_id`, …).
- **Changes:** must name allowlisted fields per target type (`organization`: name, type,
  timezone, status; `user`: full_name, is_active, is_staff, is_superuser, password). Password
  changes are stored as `{"changed": true}`.
- **Text:** credential patterns are scrubbed, control characters stripped, and length bounded.

Tests feed known secrets through the flows and assert that none appears in any stored row:
passwords, hashes, access and refresh tokens, CSRF tokens, reset tokens and user agents with
embedded credentials.

### Read APIs
- **Tenant:** `GET /api/v1/organizations/{org_id}/audit-logs/`.
  - Tenant resolution comes first: non-members, suspended or provisioning organizations and bad
    ids get 404, before any permission check.
  - Then `HasOrgPermission` requires `audit.view`. Nobody could hold it before Batch 6 roles;
    since Batch 6 (ADR-0017) it is granted to Owners, to Admins by default and to any role that
    includes it. Members without it get **403**.
  - Filters: `action`, `actor`, `outcome`, `created_after`, `created_before`.
  - Cursor pagination, newest first with an id tie-breaker; `page_size` up to 100.
  - The production view's scoping, filters and pagination are tested through a test-only route
    with a test permission.
- **Platform:** `GET /api/v1/platform/audit-logs/` (new route). Returns `platform_events()` only:
  organization history is never served here. Requires active staff with the explicit
  `audit.view_auditlog` model permission (`IsPlatformAuditor`). Organization administration
  permissions do not grant it, and there is no superuser tenant bypass.

## Batch 6 integration (done, ADR-0017)
- `audit.view` is in the catalog; Owners hold it and the Admin role has it by default. The
  endpoint opened with no view change.
- Ownership-invariant mutations (roles, memberships, deactivation across organizations) call
  `audit.record` inside their locked transactions. New events: `rbac.role.created`,
  `rbac.role.updated`, `rbac.role.permissions_changed`, `rbac.role.deleted`,
  `rbac.membership.status_changed`, `rbac.membership.removed`, `rbac.membership.roles_replaced`,
  `rbac.owner.granted`, `rbac.owner.revoked`, `rbac.owner.relinquished`. They belong to the
  organization's history.
- Redaction allowlists gained `member_user_id`, `roles_added`, `roles_removed`,
  `permissions_added`, `permissions_removed` (metadata) and `role.name`, `role.description`,
  `membership.status` (changes).

## Batch 7 integration (ADR-0018)
- Invitation and onboarding events, recorded in the mutation transaction:
  - `invitation.created`, `invitation.initial_owner_issued`, `invitation.revoked`,
    `invitation.expired`, `invitation.accepted`;
  - `invitation.email_delivered`, `invitation.delivery_failed`, `invitation.delivery_cancelled`;
  - `rbac.membership.created`, `rbac.membership.roles_assigned`, `rbac.owner.granted`;
  - `organization.activated`;
  - `auth.account.created` (`reason: invitation`).
- Independent: `invitation.accept_rejected`, `invitation.delivery_lease_lost`,
  `auth.rate_limited` (`scope: invitation`).
- New metadata keys: `invitation_id`, `initial_owner`, `account_created`. Addresses, tokens,
  digests, links and passwords are never recorded.

## Consequences
- **Durability:** every listed mutation commits with its audit row or not at all.
- **Cost:** independent security events cost one short transaction each.
- **Roles:** deployments must provision two database roles and run migrations as the owner.
- **Retention:** audit rows grow without bound until retention and archival are designed
  (deferred).
