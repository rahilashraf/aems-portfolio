# ADR-0003: Tenant isolation — shared schema, organization-scoped rows

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

AEMS serves many organizations (schools, universities, training providers) that must never see each
other's data. A single person may belong to several organizations (e.g. a lecturer at a university
who also teaches for a training provider).

## Decision

- **Shared database, shared schema.** Every tenant-owned table has a non-null `organization_id`
  and inherits `TenantScopedModel`. Users are global; tenant relationships live on `Membership`.
- **Layered application enforcement:**
  1. Tenant identified only by the URL path (`/api/v1/organizations/{org_id}/…`).
  2. Organization identifiers in request bodies are never trusted or accepted for scoping.
  3. Central resolution of the caller's active membership in an active organization; failure → 404.
  4. Membership plus explicit permission required on every tenant endpoint (default deny).
  5. Querysets obtained only through organization-scoped helpers.
  6. Nested and referenced identifiers validated against the resolved organization.
- **Mandatory tests**: a tenant-isolation matrix and a route-coverage meta-test run in CI for every
  pull request.
- **PostgreSQL Row-Level Security is deferred to Phase 2**, gated by a security review that must
  conclude before sensitive student, examination, or response records are introduced.

## RLS requirements (if adopted in Phase 2)

1. Distinct database roles: a migration/owner role and a runtime role without `BYPASSRLS` or
   superuser; `ALTER TABLE … FORCE ROW LEVEL SECURITY` on every tenant table.
2. Tenant context set with `SET LOCAL app.current_organization_id = …` inside the request
   transaction, derived only from the resolved membership; transaction-scoped so pooled connections
   cannot leak context between requests.
3. `USING` and `WITH CHECK` policies on `organization_id`; fail closed when the setting is unset
   (`current_setting(..., true)` returning NULL matches no rows).
4. Narrow, explicit, audited bypass mechanisms for legitimate cross-tenant operations (listing a
   user's organizations, platform administration), e.g. `SECURITY DEFINER` functions or a separate
   role, never a global bypass.
5. Tests that remove the application-level filter and prove the database still blocks
   cross-tenant reads and writes.
6. Performance review of policies against tenant indexes.

## Alternatives considered

| Option | Why not |
|---|---|
| Database per tenant | Strongest isolation but very high operational cost; cross-org users awkward |
| Schema per tenant (django-tenants) | Migrations run per tenant; global multi-org users conflict with per-tenant schemas |
| Tenant via header or subdomain | Hidden state, easy to misuse; subdomains can be layered on in the frontend later |
| RLS in Phase 1 | Few tenant tables yet; cross-tenant queries need bypass design; better decided with real exam data |

## Consequences

- Isolation depends on disciplined application code until RLS is decided; mitigated by central
  resolution, default-deny permissions, and mandatory automated isolation tests.
- Phase 1 already uses a non-superuser runtime role so RLS can be introduced without redesign.
