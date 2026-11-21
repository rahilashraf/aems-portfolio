# ADR-0005: Organization-scoped RBAC and ownership invariants

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

Each organization must define its own roles from a catalog of permissions. The same user may be an
administrator in one organization and an ordinary member in another. Organizations must never be
left without an Owner, and no user may escalate their own privileges, including under concurrent
requests.

## Decision

- **Code-defined permission catalog** registered by each app and synced to `rbac.Permission`.
  Every permission corresponds to a check in code.
- **Per-organization roles** (`rbac.Role`) with an M2M to permissions; system roles Owner, Admin,
  Member seeded per organization. Owner implicitly has all permissions (evaluated dynamically),
  and is immutable and undeletable.
- **Effective permissions** = union of the membership's roles, computed once per request.
  Enforcement via a DRF permission class with per-action requirements and default deny.
- **Ownership invariant**: every active organization keeps ≥ 1 active Owner. All operations that can
  reduce the Owner set lock the organization row (`SELECT … FOR UPDATE`) and then the target rows,
  re-count, and either apply the change or raise `LastOwnerError`, atomically with the audit event.
  Multi-organization operations lock organizations in id order to avoid deadlocks.
- **Escalation rules**: no self-modification of roles/status (except an Owner relinquishing
  Owner while another active Owner remains); actor must hold every permission they grant or
  assign; only Owners manage the Owner role; Owners and platform administrators pass through the
  same services and invariants — there is no bypass path.
- **Concurrency regression tests** with real transactions and synchronized threads.

## Alternatives considered

- *Django built-in Group/Permission*: global, tied to content types, cannot express per-tenant roles.
- *django-guardian*: object-level ACLs, more granularity than needed and costly at scale.
- *Optimistic checks without locking*: susceptible to write skew under READ COMMITTED (two
  concurrent demotions each see another Owner remaining).
- *SERIALIZABLE isolation*: correct but requires retry logic everywhere; a targeted row lock is
  simpler and explicit.

## Consequences

- Ownership-affecting operations are serialized per organization (acceptable: they are rare).
- Scope-level roles (per course/exam) can be added later via a nullable scope on `MembershipRole`.
