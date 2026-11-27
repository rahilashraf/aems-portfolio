# Contributing to AEMS

## Workflow

1. Work is delivered **phase by phase**; within a phase, the backend is built and approved before
   any frontend work. Each implementation batch is one pull request against `main`.
2. Create a branch from `main`; never commit directly to `main` (a pre-commit hook enforces this).
3. Keep pull requests focused on a single batch or change. Fill in the
   [pull request template](.github/pull_request_template.md).
4. Pull requests are merged only after review and explicit approval.

## Local checks

Run before pushing:

```bash
make qa
```

Pre-commit hooks (`make hooks`) run ruff, formatting, YAML/TOML checks, private-key and secret
detection, and mypy on every commit.

## Engineering standards

- **Architecture:** follow the layout in [ADR-0002](docs/adr/0002-repository-and-application-architecture.md):
  thin views/serializers, business rules in `services.py`, queries in `selectors.py`.
- **Tenancy:** tenant endpoints resolve the organization from the URL path only, require
  membership and explicit permissions, and are covered by the tenant-isolation test matrix
  ([ADR-0003](docs/adr/0003-tenant-isolation.md)).
- **Tests:** every change ships with tests; tests run against PostgreSQL; coverage must stay ≥ 90%.
- **Types:** new code passes `mypy --strict`.
- **Security:** no secrets in code, logs, or audit records; configuration via environment
  variables; dependencies pinned in `backend/uv.lock`. Every new route must be classified in
  `backend/tests/security/test_route_policy.py` (CI fails otherwise), and new user or
  organization row locks use `select_for_update(no_key=True)` (ADR-0019). Report vulnerabilities
  privately as described in [SECURITY.md](SECURITY.md).
- **Frontend:** strict TypeScript, accessible components (keyboard, labels, axe-clean), design
  tokens from `frontend/src/styles/globals.css` only, and no placeholder or non-functional
  controls. Run `make fe-qa` (and `make fe-browser` for UI changes) before pushing.
- **Decisions:** significant architectural decisions get an ADR in `docs/adr/`.

## Commit messages

Use concise, imperative subjects with a conventional prefix (`feat:`, `fix:`, `docs:`, `chore:`,
`test:`, `refactor:`, `ci:`), and explain the *why* in the body when it is not obvious.

## Dependencies

```bash
cd backend
uv add <package>            # runtime
uv add --group dev <pkg>    # development only
```

Commit both `pyproject.toml` and `uv.lock`.
