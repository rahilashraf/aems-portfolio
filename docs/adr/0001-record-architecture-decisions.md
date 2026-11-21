# ADR-0001: Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

AEMS is built phase by phase with review gates. Reviewers and future contributors need to know
not only *what* the architecture is but *why*, and which alternatives were rejected.

## Decision

Record every significant architectural decision as an ADR in `docs/adr/`, numbered sequentially,
using `template.md`. ADRs are reviewed in the same pull request as the code they govern. Accepted
ADRs are immutable except for status changes; reversals are new ADRs that supersede old ones.

## Consequences

- Decisions are discoverable and reviewable alongside code.
- Small overhead per significant decision.
