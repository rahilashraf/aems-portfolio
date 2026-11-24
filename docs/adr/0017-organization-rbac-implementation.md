# ADR-0017: Organization RBAC implementation (Batch 6)

- **Status:** Accepted
- **Date:** 2026-11-24
- **Implements:** [ADR-0005](0005-rbac-and-ownership-invariants.md); completes the authorization
  integration points of [ADR-0015](0015-organizations-and-tenancy-implementation.md) and
  [ADR-0016](0016-durable-audit-logging.md)

## Context

Batch 4 gave every tenant endpoint a permission declaration but no way to hold a permission.
Batch 5 made mutations durable and auditable. Batch 6 adds per-organization roles, the
permission engine, member and role management, and the Owner invariant, under concurrency.

## Decisions

### Permission catalog (`apps.rbac.registry`, `apps.rbac.catalog`)
- **Registration.** Each application registers the codes its code checks, from
  `AppConfig.ready()`:
  - `organizations`: `organization.view`, `organization.update`, `members.view`,
    `members.manage`, `invitations.manage`;
  - `rbac`: `roles.view`, `roles.manage`;
  - `audit`: `audit.view`.

  `invitations.manage` gates the Batch 7 invitation endpoints (ADR-0018).
- **Definition.** Code (`<category>.<action>`, immutable), description, category and a
  deprecation flag.
- **Conflicts.** Registering a code twice with a different definition fails at startup. Invalid
  codes, categories and descriptions are rejected.
- **Sync.** `sync_permissions()` runs on `post_migrate` (like the Batch 5 runtime grants). It
  upserts by code and never deletes: a code that is no longer registered is marked deprecated.
  Role-permission links and assignments are untouched, so history stays meaningful.
- **Database protection.** A trigger (`rbac_permission_protect`) makes `rbac_permission.code`
  immutable and rows undeletable. A code check constraint enforces the format.
- **Deprecated or unknown codes grant nothing.** They cannot be added to roles: the API returns
  400 and the service raises `UnknownPermissionError`. A route-coverage test asserts that every
  permission declared by a tenant view is an active catalog code.

### Models (`apps.rbac`, migrations `rbac.0001`–`0003`, `organizations.0002`)
- **`Permission`:** `id`, `code` (unique), `description`, `category`, `is_deprecated`.
- **`Role`** (`TenantScopedModel`): `name`, `description`, `is_system`, `system_key`
  (`owner`/`admin`/`member`/NULL), `permissions` (M2M), timestamps. Constraints:
  - `rbac_role_org_name_ci_uniq`: name unique per organization, ignoring case;
  - `rbac_role_org_system_key_uniq`: one role per system key per organization;
  - `rbac_role_system_key_valid`, `rbac_role_system_flag_matches_key`,
    `rbac_role_name_not_blank`;
  - `rbac_role_id_org_uniq`: target of the composite foreign key below.
- **`MembershipRole`** (`TenantScopedModel`): `membership` (CASCADE), `role` (PROTECT),
  `assigned_by`, `assigned_at`. Constraint `rbac_membershiprole_membership_role_uniq`.
- **Cross-tenant assignments are impossible at three levels:**
  - the service resolves roles within the URL organization only;
  - `MembershipRole.save()` refuses a membership, role and organization that disagree;
  - composite foreign keys (`rbac_mrole_membership_same_org_fk`, `rbac_mrole_role_same_org_fk`,
    migration `rbac.0002`) reference `(id, organization_id)` of both rows. PostgreSQL therefore
    rejects raw SQL and `bulk_create` too. `organizations.0002` adds the matching unique
    `(id, organization_id)` on memberships.
- **No Django `Group`/`Permission`.** They remain platform (staff) permissions only.

### System roles and seeding
| Role | Permissions | Editable |
|---|---|---|
| Owner | every active catalog permission, evaluated dynamically (none stored) | No: cannot be renamed, edited or deleted |
| Admin | default: all eight Phase 1 permissions | Permissions only; cannot be renamed or deleted |
| Member | default: `organization.view` | Permissions only; cannot be renamed or deleted |

- **New organizations.** `create_organization()` seeds the three roles in its transaction; a
  seeding failure rolls the organization back. Admin and Member get their defaults once.
  Catalog additions later extend Owner only.
- **Existing organizations.** Migration `rbac.0003` (frozen catalog) creates the permission rows
  and seeds the three roles. It assigns **no** roles, so existing memberships gain nothing.
- **Seeding is not ownership.** It never assigns the Owner role and never changes the
  organization's status. Provisioning → active remains the Batch 7 initial-Owner acceptance.
  Tests build active organizations with Owners through test-only helpers (`activate_for_tests`,
  `apps.rbac.tests.conftest.grant`), which application code may not import (asserted).

### Permission evaluation (`apps.rbac.engine`)
- **Effective permissions.** The union of the membership's role permissions; the Owner role
  means the full active catalog. One query computes it, and it counts only while:
  - the account is active;
  - the membership is active;
  - the organization is active;
  - each role belongs to the membership's organization.
- **Discarded codes.** Codes deprecated in the registry or in the database, and unknown codes,
  are dropped.
- **No other source of authority.** Staff, superuser and Django model permissions play no part.
- **Caching.** `HasOrgPermission` (`membership_has_permissions`) uses `engine.has_permissions`,
  memoized on the membership *instance*. The tenant mixin resolves a new instance on every
  request, so nothing is cached across requests.
- **Default deny.** Undeclared actions and unknown codes are denied. View declarations are
  unchanged from Batch 4.

### Mutation protocol (`apps.rbac.services`)
Every authorization-sensitive mutation runs in one transaction:
1. Lock the organization row.
2. Lock the actor's and the target memberships, in ascending id order.
3. Recompute the actor's permissions from current state with `fresh_permissions`, never the
   request cache, and re-check the required permission.
4. Re-check the self-modification, delegation and Owner rules.
5. Re-count active Owners.
6. Apply the change.
7. Write the audit records in the same transaction.

The request-level check is only an early rejection; the in-transaction check is
authoritative. The organization profile update (`organization.update`) uses the same re-check
(`require_fresh_permission`).

### Rules
- **No self-modification.** Actors cannot change their own status, remove their own membership,
  or change their own roles. The only exception: an Owner removing exactly their own Owner role,
  and nothing else, while another active Owner remains (`rbac.owner.relinquished`).
- **Delegation.** The actor must hold every permission involved:
  - permissions added to or removed from a role;
  - the permissions conferred by roles assigned or removed;
  - for suspension, reactivation and removal, the permissions conferred by the target's roles.

  So a role the actor holds, even one shared with others, cannot be used to raise the actor's own
  permissions. Self-demotion is allowed.
- **Owner-only operations.** Granting or removing the Owner role, and suspending, removing or
  changing the roles of an Owner. A custom role holding every permission is not Owner.
- **System roles.** The Owner role is immutable. Admin and Member keep their names but have
  editable permissions. System roles cannot be deleted.
- **Role deletion.** A custom role that is still assigned cannot be deleted (409 `role_in_use`;
  the foreign key is also `PROTECT`). This avoids silent bulk permission loss.
- **Error codes:**
  - 403: `permission_denied`, `delegation_not_allowed`, `owner_role_restricted`,
    `self_modification_not_allowed`;
  - 409: `last_owner`, `system_role_protected`, `role_name_taken`, `role_in_use`;
  - 400: validation errors, including unknown permission codes and role ids.

### Owner invariant and lock order
- **Invariant.** Every active organization keeps at least one active Owner: an active account
  with an active membership holding the organization's Owner role.
- **Enforcement.** These operations refuse with `LastOwnerError` (409 `last_owner`) after
  re-counting under the organization lock:
  - suspending a membership;
  - removing a membership;
  - removing the Owner role (including relinquishing it);
  - globally deactivating a user.
- **Global lock order:** user row → organization rows (ascending id) → membership rows
  (ascending id) → role rows.
  - Membership and role operations start at the organization and never lock user rows.
  - `accounts.services.deactivate_user` locks the user row, then **every organization in which
    the user has a membership**, in ascending id order, and re-counts the other active Owners
    in each active one. All blocking organizations are listed in `LastOwnerError.organization_ids`
    (for internal callers such as the staff admin), and the whole deactivation rolls back.
- **Why all of the user's organizations, not only those where the user is an Owner.** The user
  could be made Owner of another organization after the read and before the lock. That
  organization's other Owner could then relinquish while the deactivation commits. Every
  operation that changes someone's Owner status holds that organization's lock, so locking all
  of the user's organizations closes the gap. The set cannot grow while the user row is locked,
  provided Batch 7 invitation acceptance locks the user row before the organization.
- **API responses** never list organization ids. The staff admin's user form shows the blocking
  organizations (staff only) before the locked check runs.

### APIs (`/api/v1/organizations/{org_id}/…`)
| Route | Permission |
|---|---|
| `GET members/`, `GET members/{id}/` | `members.view` |
| `PATCH members/{id}/` (`status`), `DELETE members/{id}/` | `members.manage` |
| `PUT members/{id}/roles/` (`role_ids`) | `members.manage` (+ Owner/delegation rules) |
| `GET roles/`, `GET roles/{id}/`, `GET permissions/` | `roles.view` |
| `POST roles/`, `PATCH roles/{id}/`, `DELETE roles/{id}/` | `roles.manage` |
| `PATCH /` (organization profile) | `organization.update` |
| `GET /` (organization profile) | `organization.view` (AEMS-017; Member, Admin and Owner hold it by default) |
| `GET me/` | any active member, with or without `organization.view`; includes `roles` and effective `permissions` |
| `GET audit-logs/` | `audit.view` (now grantable) |

- **Conventions.** All routes use the tenant mixin and `HasOrgPermission`, enforced by the
  route-coverage meta-test. They also share:
  - organization-scoped lookups: foreign or malformed ids are 404, and foreign role ids in bodies
    are 400 exactly like unknown ids;
  - strict input allowlists;
  - validated filters (`status`, `is_system`) and allowlisted ordering with an id tie-breaker;
  - standard pagination.
- **Membership statuses.** `active` and `suspended`; reactivation follows the same rules.
- **No new flows.** There is no membership creation or self-removal (Batch 7 invitations create
  memberships).
- **Admin.** Read-only for permissions, roles and assignments. Staff deactivation goes through
  the Owner-checked service.

### Audit integration
These events are recorded inside the mutation transaction:
- `rbac.role.created`, `rbac.role.updated`, `rbac.role.permissions_changed`,
  `rbac.role.deleted`;
- `rbac.membership.status_changed`, `rbac.membership.removed`,
  `rbac.membership.roles_replaced`;
- `rbac.owner.granted`, `rbac.owner.revoked`, `rbac.owner.relinquished`.

The existing `auth.account.deactivated` and `organization.profile_updated` events are also
recorded in their transactions.

- **Redaction allowlists.**
  - New metadata keys: `member_user_id` (UUID), `roles_added`/`roles_removed` (UUID lists),
    `permissions_added`/`permissions_removed` (catalog codes).
  - New change fields: `role.name`, `role.description`, `membership.status`.
- **No-op requests** write and record nothing.
- **Audit failure.** If the audit insert fails, the mutation rolls back.

### Organization profile access (review finding AEMS-017)
`GET /organizations/{org_id}/` requires `organization.view` through `HasOrgPermission`. Before
AEMS-017 it was a member action, readable by any active member. It is now a permission-gated
action like every other tenant read:
- The default Member role keeps `organization.view`, so ordinary members are unaffected.
- A member with no role, or only roles without the permission, gets 403. Revoking the permission
  takes effect on the next request.
- Tenant resolution is unchanged. Suspended memberships, suspended or provisioning
  organizations, non-members, other tenants and platform staff or superusers without a
  membership get 404; unauthenticated callers get 401.
- `GET /organizations/{org_id}/me/` stays a member action: every active member can always read
  their own membership, roles and effective permissions.

## Deviations from the plan (approved in the Batch 6 review)
1. **`MembershipRole` lives in `apps.rbac`**, not `apps.organizations` (plan §5.3), as the Batch 6
   authorization requires a dedicated RBAC app. The composite foreign keys keep it bound to the
   membership's organization.
2. **Delegation also covers status changes and removal**: suspending or removing a member requires
   authority over every permission that member holds. The plan states delegation for grants and
   assignments only.
3. **Only Owners modify memberships belonging to Owners** (status, removal and roles).
4. **Assigned custom roles cannot be deleted** (409 `role_in_use`) rather than being removed from
   their holders.
5. **Database-level safeguards beyond the plan:**
   - composite foreign keys;
   - immutable, undeletable permission rows;
   - deprecation kept in the database.
6. **Deactivation locks every organization of the user**, not only those where the user is an
   Owner (see above).
7. **Not added:**
   - platform RBAC endpoints (plan §6.4 mentions them): deferred, no workflow invented;
   - `suspended → active` reactivation: stays disabled;
   - the initial Owner invitation and `provisioning → active`: Batch 7;
   - self-service leaving of an organization.

## Batch 7 dependencies (implemented, ADR-0018)
- **Invitation acceptance:**
  - lock the accepting user row **before** the organization row (lock order);
  - create the membership and its roles through the same validation;
  - for the initial Owner, assign the Owner role and switch `provisioning → active` in one
    transaction, with audit records.
- **Invitations carrying roles:** `invitations.manage` plus the delegation rules at creation, and
  again at acceptance under the organization lock.
- **Role deletion:** a role that a pending invitation would grant cannot be deleted
  (409 `role_in_use`).
- **Reactivation:** `suspended → active`, if added, must verify an active Owner under the
  organization lock.

## Consequences
- RBAC mutations and deactivations serialize per organization (rare operations).
- Every tenant request costs one membership query plus, for permission-gated actions, one
  permission query.
- The Owner invariant, delegation, stale-permission protection and cross-tenant isolation are
  covered by unit, API, migration, mutation and multi-threaded PostgreSQL tests.
