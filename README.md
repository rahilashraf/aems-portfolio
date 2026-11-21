# AEMS — Assessment & Examination Management System

AEMS is a multi-organization SaaS platform for schools, universities, and training organizations,
supporting online and paper-based examinations with strict tenant isolation and customizable,
organization-scoped roles and permissions.

> **Status:** Phase 1 — Backend Foundation, Batch 1 (repository scaffolding).
> See the [Phase 1 plan](docs/phase-1-plan.md) and [Architecture Decision Records](docs/adr/README.md).

## Technology

| Layer | Stack |
|---|---|
| Backend | Python 3.13, Django 5.2 LTS (Django REST Framework from Batch 2) |
| Database | PostgreSQL 17 |
| Frontend | Next.js, React, TypeScript (after backend approval) |
| Tooling | uv, ruff, mypy (strict), pytest, bandit, pip-audit, pre-commit |
| Dev environment | Docker Compose (PostgreSQL, backend, Mailpit) |
| CI | GitHub Actions (Batch 2) |

## Repository layout

```
backend/            Django project
  config/           settings (base/local/test/production), URLs, WSGI/ASGI
  apps/core/        shared infrastructure (health checks in Batch 1)
docker/postgres/    database bootstrap scripts (least-privilege runtime role)
docs/               Phase plan, ADRs, architecture notes
docker-compose.yml  local development stack
Makefile            developer commands (`make help`)
```

## Quick start (Docker)

Prerequisites: Docker with Compose v2, GNU Make.

```bash
cp .env.example .env     # development-only defaults; edit as needed
make up                  # builds and starts db, backend, mailpit
```

| Service | URL |
|---|---|
| Backend liveness | http://localhost:8000/health/live/ |
| Backend readiness | http://localhost:8000/health/ready/ |
| Mailpit (email UI) | http://localhost:8025/ |

Run the tests inside the container:

```bash
make docker-test
```

Stop the stack (database data is kept in a named volume):

```bash
make down
```

## Host development (faster feedback)

Prerequisites: [uv](https://docs.astral.sh/uv/) and Python 3.13. The database still runs in Docker.

```bash
make env install hooks   # .env, dependencies, git hooks
docker compose up -d db
make test                # pytest + coverage gate (90%)
make qa                  # every quality gate
```

| Command | Purpose |
|---|---|
| `make test` | Tests with branch coverage; fails below 90% |
| `make lint` / `make format` | ruff lint + formatting |
| `make typecheck` | mypy (strict) with django-stubs |
| `make security` | bandit static analysis |
| `make audit` | pip-audit against the locked dependency set |
| `make check-migrations` | Fails if models and migrations diverge |
| `make deploy-check` | `manage.py check --deploy` against production settings |
| `make qa` | All of the above |

## Health endpoints

| Endpoint | Meaning | Checks |
|---|---|---|
| `GET /health/live/` | Process is up | none (never touches dependencies) |
| `GET /health/ready/` | Ready to serve traffic | PostgreSQL `SELECT 1`; returns `503` if unavailable |

Responses are uncached and never include internal error details.

## Configuration

All configuration comes from environment variables (see [`.env.example`](.env.example)).
`config.settings.production` refuses to start when `DJANGO_DEBUG` is true, `DJANGO_SECRET_KEY`
is missing, short, or a placeholder, or `DJANGO_ALLOWED_HOSTS` is empty or contains `*`.

The application connects to PostgreSQL as a non-superuser role (`aems_app`) created by
[`docker/postgres/init/01-create-app-role.sh`](docker/postgres/init/01-create-app-role.sh).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
