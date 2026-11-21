## Summary

<!-- What does this PR change and why? Link the phase/batch and any ADRs. -->

## Scope

- Phase / batch:
- Out of scope (explicitly not included):

## Changes

-

## Security & tenancy checklist

- [ ] No secrets, tokens, or credentials committed or logged
- [ ] Tenant-scoped endpoints resolve the organization from the URL and check membership + permission
- [ ] No organization identifier is trusted from request bodies
- [ ] Sensitive mutations write audit events in the same transaction
- [ ] Not applicable (explain):

## Testing

- [ ] `make lint`
- [ ] `make typecheck`
- [ ] `make test` (coverage ≥ 90%)
- [ ] `make security` / `make audit`
- [ ] `make check-migrations`

## Documentation

- [ ] README / docs / ADRs updated where needed
