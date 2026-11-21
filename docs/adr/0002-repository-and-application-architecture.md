# ADR-0002: Repository and application architecture

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

AEMS has a Django/DRF backend and (later) a Next.js frontend sharing an API contract. The backend
will grow through several domain phases (examinations, paper-based workflows, grading) whose
business rules must be reusable from HTTP views, background jobs, and management commands.

## Decision

1. **Monorepo**: `backend/`, `frontend/` (later), `docs/`, `.github/` in one repository. The
   generated OpenAPI schema is committed under `docs/api/` as the backend–frontend contract.
2. **Django project layout**: `backend/config/` (settings split into `base`, `local`, `test`,
   `production`; URL roots; WSGI/ASGI) and `backend/apps/<app>/` domain apps (`core`, `accounts`,
   `organizations`, `rbac`, `audit`).
3. **Service/selector layer**: writes in `services.py` (transactions, locking, invariants,
   authorization rules, audit), reads in `selectors.py`. Views and serializers stay thin.
4. **12-factor configuration** via environment variables (`django-environ`); production refuses
   to start with insecure configuration.
5. **uv** for dependency management with a committed lockfile; Python 3.13; Django 5.2 LTS.
6. **No `django.contrib.auth`/`admin` before the custom user model**: Batch 1 installs no apps
   with user-related migrations, so the first auth migration is the custom user (Batch 3).

## Alternatives considered

- *Separate repositories*: contract changes would span repositories and pull requests.
- *Fat serializers / logic in views*: idiomatic for small DRF apps but not reusable outside HTTP
  and harder to unit test.
- *Poetry / pip-tools*: viable; uv is faster and offers reproducible `--frozen` installs.
- *Django 6.x*: newer, but a non-LTS line; 5.2 LTS is supported until April 2028.

## Consequences

- Slightly more indirection (service functions) in exchange for reusable, testable rules.
- CI uses path filters so backend jobs run only when relevant files change.
