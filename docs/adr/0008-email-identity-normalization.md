# ADR-0008: Email identity normalization and case-insensitive uniqueness

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

Email is the login identifier and must be unique regardless of case. Django's PostgreSQL
`CIEmailField`, `CITextField`, and `CICharField` were deprecated in Django 4.2 and removed in 5.1,
so they cannot be used on Django 5.2.

## Decision

- Store email in a standard `EmailField`.
- Normalize on every write and lookup through one helper: strip whitespace, Unicode NFKC, lowercase.
- Enforce uniqueness in the database with a functional constraint:
  `UniqueConstraint(Lower("email"), name="accounts_user_email_ci_uniq")`, so uniqueness holds even
  if a code path skips normalization.
- Create users inside `transaction.atomic()`; catch `IntegrityError` for this constraint in a
  savepoint and map it to a domain error. Application-level "exists" checks are for UX only.
- Invitations use the same normalization with a partial functional unique constraint for
  pending invitations per organization.

## Alternatives considered

- *`citext` column via custom field*: works but reintroduces what Django removed and needs an extension.
- *Nondeterministic ICU collation (`db_collation`)*: supported by Django 5.2, but on PostgreSQL < 18
  pattern lookups (`LIKE`, `icontains`, `startswith`) fail on nondeterministic collations,
  affecting admin search and filtering.
- *Normalization without a database constraint*: race-prone and bypassable.

## Consequences

- Lowercasing the local part treats `Alice@x` and `alice@x` as the same account, matching user
  expectations and virtually all real mail providers.
- Lookups always use the normalized value to hit the index.
