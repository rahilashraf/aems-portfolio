# Architecture Decision Records

ADRs record significant architectural decisions, their context, and their consequences, using a
lightweight [Michael Nygard](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
format. New ADRs copy [`template.md`](template.md) and take the next number. Accepted ADRs are not
rewritten; a change of direction is recorded in a new ADR that supersedes the old one.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-repository-and-application-architecture.md) | Repository and application architecture | Accepted |
| [0003](0003-tenant-isolation.md) | Tenant isolation: shared schema, organization-scoped rows | Accepted |
| [0004](0004-authentication-and-session-management.md) | Authentication and session management | Accepted |
| [0005](0005-rbac-and-ownership-invariants.md) | Organization-scoped RBAC and ownership invariants | Accepted; implemented by 0017 |
| [0006](0006-audit-logging.md) | Audit logging | Accepted |
| [0007](0007-api-error-format.md) | API error format (RFC 9457) | Accepted; refined by 0009 |
| [0008](0008-email-identity-normalization.md) | Email identity normalization and case-insensitive uniqueness | Accepted |
| [0009](0009-api-error-response-conventions.md) | API error response conventions | Accepted |
| [0010](0010-request-correlation-and-structured-logging.md) | Request correlation and structured logging | Accepted |
| [0011](0011-continuous-integration.md) | Continuous integration and required checks | Accepted |
| [0012](0012-api-access-control-enforcement.md) | API access-control enforcement and the public-endpoint allowlist | Accepted |
| [0013](0013-authentication-implementation-and-security-events.md) | Authentication implementation and the security-event boundary | Accepted |
| [0014](0014-password-reset-email-outbox.md) | Password-reset email outbox | Accepted |
| [0015](0015-organizations-and-tenancy-implementation.md) | Organizations and tenancy implementation | Accepted |
| [0016](0016-durable-audit-logging.md) | Durable audit logging, database roles and audit APIs | Accepted |
| [0017](0017-organization-rbac-implementation.md) | Organization RBAC implementation | Accepted |
