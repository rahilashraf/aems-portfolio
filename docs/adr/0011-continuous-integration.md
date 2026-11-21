# ADR-0011: Continuous integration and required checks

- **Status:** Accepted
- **Date:** 2026-11-22

## Context

Batch 2 introduces GitHub Actions. CI must verify everything the local `make qa` verifies, plus
what cannot be trusted in a development sandbox (a clean Docker build), without becoming a supply
chain risk or a way to bypass required checks.

## Decision

Workflow `.github/workflows/backend-ci.yml` (**Backend CI**):

| Job (check name) | Verifies |
|---|---|
| `Lint & type check` | locked install (`uv sync --frozen`), ruff lint and format, strict mypy, repository hygiene hooks |
| `Tests & migrations` | PostgreSQL 17 service; non-superuser `aems_app` role created by the same script used by Docker Compose; Django system checks; fresh `migrate`; no default auth tables; migration drift (application and test settings); full pytest suite with branch coverage ≥ 90%; coverage and JUnit artifacts |
| `Security` | Bandit, pip-audit against the lockfile, detect-secrets against the committed baseline, `check --deploy` on production settings |
| `API contract` | OpenAPI generation with `--validate --fail-on-warn`; fails if `docs/api/openapi.yaml` differs |
| `Docker image` | `docker build --pull --no-cache` of the committed Dockerfile `prod` target; non-root user and no dev tooling; refusal of `DJANGO_DEBUG=true`; container reaches `healthy` via its own `HEALTHCHECK`; live/ready/API/docs/HTTPS-redirect/Host-validation behaviour |
| `Backend CI result` | aggregates all jobs; fails unless every job succeeded |

Controls:

- **Triggers:** `pull_request` to `main` and `push` to `main`, **without path filters**, so the
  required checks always report. There is no `pull_request_target`. Manual dispatch is not
  configured.
- **Permissions:** `contents: read` only. Checkout uses `persist-credentials: false`.
- **Supply chain:** third-party actions are pinned to full commit SHAs (resolved from the upstream
  release tags, with the version in a comment). Dependabot proposes updates. The uv version is
  pinned.
- **Isolation:** no secrets and no production credentials. The database passwords are throwaway
  values for ephemeral service containers. Nothing is pushed, published or deployed.
- **Concurrency:** superseded pull-request runs are cancelled. Pushes to `main` always complete.
- **Timeouts** on every job.
- **Make targets** are the single source of truth, so CI and local runs (`make qa`) execute the
  same commands.

## Recommended branch protection (owner action)

Require the single aggregate check **`Backend CI result`**. It depends on every job above, so new
jobs are covered without changing protection settings. Alternatively, require each job check by
name: `Lint & type check`, `Tests & migrations`, `Security`, `API contract`, `Docker image`.
Also recommended: require branches to be up to date before merging, and require pull requests for
`main`.

## Consequences

- Every pull request runs every job, including documentation-only changes (a few minutes of
  runner time) in exchange for checks that cannot be skipped.
- The Docker job is the authoritative clean-build verification. Local sandbox builds that needed
  certificate workarounds are not evidence of a clean build.
