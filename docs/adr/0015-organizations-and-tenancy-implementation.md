# ADR-0015: Organizations and tenancy implementation (Batch 4)

- **Status:** Accepted
- **Date:** 2026-11-22
- **Implements:** [ADR-0003](0003-tenant-isolation.md) (Phase 1 layers);
  prepares [ADR-0005](0005-rbac-and-ownership-invariants.md) (RBAC, Batch 6)

## Context

Batch 4 adds organizations, memberships and the tenant-scoping foundation every later tenant API
builds on. Its full design depends on two later batches:
- RBAC (Owner role, permission evaluation) arrives in Batch 6.
- Invitations, which turn a provisioning organization active, arrive in Batch 7.

So Batch 4 must prepare the lifecycle and authorization without inventing shortcuts.

## Decisions

### Models (`apps.organizations`, migration `organizations.0001_initial`)
- **`Organization`**: not tenant-scoped itself.
  - UUIDv4 primary key, `name`, `slug`, `organization_type`, `status`, `timezone` (IANA, default
    `UTC`), `created_at`, `updated_at`, and `created_by` (`PROTECT`, because users are
    deactivated, never deleted).
  - `organization_type` is `school`, `university`, `training` or `other`. `status` is
    `provisioning`, `active` or `suspended`.
  - Database constraints:
    - `organizations_org_slug_uniq`;
    - `organizations_org_slug_format`: lowercase ASCII, hyphen-separated, 3–63 characters,
      validated in Python too;
    - `organizations_org_name_not_blank`, `organizations_org_type_valid` and
      `organizations_org_status_valid`.
  - Index `orgs_org_status_name_idx`.
  - Timezones must be a location identifier from the runtime's IANA database.
- **`Membership`** (tenant-scoped): `organization`, `user` (`PROTECT`), `status` (`active` or
  `suspended`) and `joined_at`.
  - Constraints: `organizations_membership_org_user_uniq` (one membership per user and
    organization) and `organizations_membership_status_valid`.
  - Index `orgs_membership_user_status`.
  - A user can hold memberships in many organizations.
- **Not added:** `MembershipRole` (Batch 6) and `Invitation` (Batch 7). No speculative columns.

### TenantScopedModel
Abstract base (`apps.organizations.tenancy`) for every tenant-owned model.
- **`organization`** is a non-null, indexed `PROTECT` foreign key, with `editable=False` so model
  forms and `ModelSerializer` never expose it.
- **Immutable (application level).** Any attempt to change it raises `TenantReassignmentError` and
  writes nothing. Covered paths:
  - `save()`, including `update_fields`, `force_update`, `update_or_create()` and rows loaded with
    `only()`/`defer()`;
  - `QuerySet.update()` and `bulk_update()`;
  - `bulk_create(update_conflicts=True)` whose `update_fields` name `organization` or
    `organization_id` (review finding AEMS-012).

  Plain bulk inserts and conflict updates of other fields still work. No reassignment service
  exists.
- **Deferred organization field (AEMS-013).** `from_db()` records the loaded organization id, or
  "unknown" when the field is deferred.
  - A record whose organization is still deferred saves without touching or querying it.
  - A lazy load or `refresh_from_db()` that really reloads the field updates the baseline; a
    refresh of other fields does not.
  - Only an instance whose stored organization was never loaded (for example a forced update of an
    object built in memory) costs one query to read the stored value.
- **Updates never write the organization column (AEMS-014).**
  - An UPDATE issued by `save()` always leaves out `organization_id`: the full save uses explicit
    `update_fields` without it, and the organization is removed from caller-supplied
    `update_fields`.
  - The baseline is the organization last read from (load, lazy load, reload) or inserted into
    the database. Updates never change it, whether partial, empty, failed or rolled back. A
    reassignment made in memory therefore still fails at the next save that would write it, and
    a stale instance cannot undo a change made elsewhere.
  - As a consequence, saving an instance whose row has been deleted raises `DatabaseError`
    instead of silently re-inserting the row.
- **Outside this enforcement.** These checks are **not database-enforced**. Raw SQL, data migrations
  (historical models), `loaddata` (which saves with `raw=True`) and direct calls to Django
  internals can still change `organization_id`. Database-level immutability would need a trigger
  or RLS (Phase 2).
- **`Model.objects.for_organization(org)`** fails closed: it raises `MissingTenantContextError`
  for a missing or unsaved organization. Saving without an organization raises too.
- **Default manager.** It still returns all rows, because Django internals need that. Tenant API
  views cannot use it directly (see the route meta-test). Cross-tenant reads exist only as named
  selectors:
  - `resolve_active_membership`;
  - `memberships_for_user`;
  - `organizations_for_platform`.

  These are the bypasses a future RLS design would have to allow explicitly.

### Lifecycle (no activation in Batch 4)
| Transition | Batch 4 | Owner of the transition |
|---|---|---|
| create → `provisioning` | Platform API (always `provisioning`) | — |
| `provisioning` → `active` | **Rejected (409)** | Batch 7: initial Owner invitation acceptance, atomically |
| `active` → `suspended` | Allowed; immediate for tenant APIs | Batch 4 |
| `suspended` → `active` | **Rejected (409)** | Batches 6/7: re-check an active Owner under lock |
| `provisioning` → `suspended`, `→ provisioning` | Rejected (409) | — |

- **No activation path.** No API, service or admin action can make an organization `active`;
  the admin is read-only for organizations and memberships.
- **Test fixture.** Tests that need active organizations use a test-only helper
  (`activate_for_tests` in `apps/organizations/tests/conftest.py`). A test asserts no
  application module references it.

### Tenant resolution: `OrganizationScopedViewMixin` (`apps.organizations.scoping`)
1. **URL only.** The organization comes from `/api/v1/organizations/<uuid:org_id>/…`. Malformed
   ids do not match the route (404), and headers are ignored.
2. **Authentication first.** Unauthenticated callers get 401 before any lookup.
3. **One query** resolves the caller's *active* membership in an *active* organization for an
   *active* user. Every failure gets the same 404 body and headers and records
   `tenant.access_denied`:
   - unknown or foreign organization;
   - provisioning or suspended organization;
   - suspended membership;
   - inactive account;
   - platform administrator without a membership.
4. **Permissions.** `HasOrgPermission` then runs with `request.membership` set.
5. **Bodies cannot name the organization.** Keys `organization`, `organization_id`, `org`,
   `org_id` and `tenant` are rejected with 400.
6. **Scoped data access.** Querysets come only from `get_scoped_queryset()`. Nested objects use
   `get_scoped_object_or_404()`, which returns 404 for foreign or malformed ids. Body references use
   `TenantScopedPrimaryKeyRelatedField`, which reports foreign ids exactly like nonexistent ones.

### Authorization until Batch 6
- **Platform administration** (`IsPlatformAdministrator`) requires all of:
  - an active account;
  - `is_staff`;
  - the Django model permission for the method: `view_organization`, `add_organization` or
    `change_organization`. Superusers hold all of them.

  Platform status never implies tenant membership.
- **Tenant endpoints** use `HasOrgPermission` with per-action declarations:
  - `member_actions`: read-only actions any active member may use, honoured for safe methods only.
  - `required_permissions`: everything else. `membership_has_permissions()` returns **False** in
    Batch 4, so every permission-gated action fails closed (403).
  - Undeclared actions are denied.
- **Batch 6** replaces `membership_has_permissions()` with the RBAC engine. Views keep their
  declarations.

### Endpoints
| Route | Status in Batch 4 |
|---|---|
| `GET/POST /platform/organizations/`, `GET/PATCH /platform/organizations/{id}/` | Active |
| `GET /organizations/` | Active: the caller's active memberships in active organizations only |
| `GET /organizations/{org_id}/`, `GET /organizations/{org_id}/me/` | Active (any active member) |
| `PATCH /organizations/{org_id}/` | Routed, requires `organization.update`: **403 until Batch 6** |
| `members/`, `roles/`, `permissions/` | Deferred to Batch 6 |
| `invitations/`, `/invitations/{token}/…` | Deferred to Batch 7 |
| `audit-logs/` | Deferred to Batch 5 |

`/organizations/{org_id}/me/` returns the organization and the membership. Roles and effective
permissions are added in Batch 6.

### Enforcement tests
- **Isolation matrix.** Seven caller types against five targets on every tenant route, plus a
  test-only tenant resource (`tests.fixtures_app.TenantNote`) for nested lookups, cross-tenant
  writes, body references and body-supplied organizations.
- **Route-coverage meta-test.** Every production route under `organizations/<uuid:org_id>/` must:
  - use the mixin (its `check_permissions`, `initial` and `get_queryset` are not overridden);
  - use `[HasOrgPermission]` only, and set no static `queryset`;
  - declare every handler;
  - not be public.

  Platform routes must use `[IsPlatformAdministrator]`.
- **Mutation testing.** Removing any isolation check, one at a time, makes the suite fail.

### Security events (Batch 5 interface)
| Event | When |
|---|---|
| `organization.created` | after commit |
| `organization.updated` | after commit; `changed_fields` |
| `organization.status_changed` | after commit; `previous_status`, `status` |
| `organization.profile_updated` | after commit; Batch 6 path |
| `tenant.access_denied` | immediate |

Events carry identifiers only. Batch 5 persists them durably; until then they exist only in logs.

## Batch 5–7 integration requirements
- **Batch 5:** persist the events above, inside the transaction for mutations.
- **Batch 6:**
  - Implement roles, `MembershipRole` and the permission catalog.
  - Replace `membership_has_permissions()` with the engine.
  - Extend `/me/` with roles and effective permissions.
  - Add `members/` and `roles/`, and enforce the ownership invariant under lock, including in
    `accounts.services.deactivate_user`.
  - Gate `suspended → active` on an active Owner.
- **Batch 7:** invitations. Accepting an initial-Owner invitation creates the Owner membership and
  performs `provisioning → active` in one transaction. That is the only activation path.

## RLS readiness (Phase 2, ADR-0003)
Nothing here blocks RLS:
- tenant rows carry a non-null `organization_id`;
- the runtime database role is not a superuser;
- tenant context is resolved in one place;
- cross-tenant reads are three named selectors.

The security review gate before sensitive student, examination or response records remains
mandatory.

## Consequences
- Every tenant request costs one indexed membership query.
- Members can read their organization but change nothing until Batch 6.
- A newly created organization stays unusable (provisioning) until Batch 7.
- Isolation relies on application enforcement plus mandatory tests until RLS is decided.
