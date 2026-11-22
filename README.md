# AEMS — Assessment & Examination Management System

AEMS is a multi-organization SaaS platform for schools, universities, and training organizations,
supporting online and paper-based examinations with strict tenant isolation and customizable,
organization-scoped roles and permissions.

> **Status:** Phase 1 — Backend Foundation, Batch 3 (accounts and authentication).
> See the [Phase 1 plan](docs/phase-1-plan.md) and [Architecture Decision Records](docs/adr/README.md).

## Technology

| Layer | Stack |
|---|---|
| Backend | Python 3.13, Django 5.2 LTS, Django REST Framework, django-filter, drf-spectacular, structlog |
| Database | PostgreSQL 17 |
| Frontend | Next.js, React, TypeScript (after backend approval) |
| Tooling | uv, ruff, mypy (strict), pytest, bandit, pip-audit, pre-commit |
| Dev environment | Docker Compose (PostgreSQL, backend, Mailpit) |
| CI | GitHub Actions ([Backend CI](.github/workflows/backend-ci.yml)), Dependabot |

## Repository layout

```
backend/            Django project
  config/           settings (base/local/test/production), URLs, WSGI/ASGI
  apps/core/        shared infrastructure: health checks, base models, request context,
                    structured logging, Problem Details errors, API conventions, OpenAPI
  tests/            test-only fixture app (never installed outside the test settings)
docker/postgres/    database bootstrap scripts (least-privilege runtime role)
docs/               Phase plan, ADRs, committed OpenAPI schema (docs/api/openapi.yaml)
.github/            CI workflow, Dependabot, PR template
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
| API root | http://localhost:8000/api/v1/ |
| API docs (Swagger UI / ReDoc) | http://localhost:8000/api/docs/ · http://localhost:8000/api/redoc/ |
| OpenAPI schema | http://localhost:8000/api/schema/ |
| Backend liveness | http://localhost:8000/health/live/ |
| Backend readiness | http://localhost:8000/health/ready/ |
| Mailpit (email UI) | http://localhost:8025/ |
| Mailpit SMTP (host-based Django) | `localhost:1025` |

All ports bind to `127.0.0.1` only; override them with the `*_HOST_PORT` variables in `.env`.
Containerized Django sends mail to `mailpit:1025`; host-based Django uses `EMAIL_URL` from `.env`
(`smtp://localhost:1025`). To check delivery, run `make sendtestemail` (host) or
`docker compose exec backend python manage.py sendtestemail dev@example.test` and open the
Mailpit UI.

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
docker compose up -d db mailpit
make migrate             # apply migrations to the database in DATABASE_URL
make test                # pytest + coverage gate (90%)
make qa                  # every quality gate
```

Create a platform administrator, then sign in at http://localhost:8000/admin/ (path configurable
with `DJANGO_ADMIN_URL`):

```bash
uv --directory backend run python manage.py createsuperuser
```

Variables passed on the command line or in the environment override `.env` for `make` targets, for
example `DATABASE_URL=postgres://... make migrate` migrates that database.

| Command | Purpose |
|---|---|
| `make test` | Tests with branch coverage; fails below 90% (extra pytest args: `PYTEST_ARGS=...`) |
| `make lint` / `make format` | ruff lint + formatting |
| `make typecheck` | mypy (strict) with django-stubs and DRF stubs |
| `make check` | Django system checks, including the public-endpoint allowlist |
| `make security` | bandit static analysis |
| `make audit` | pip-audit against the locked dependency set |
| `make secrets` | detect-secrets scan against `.secrets.baseline` (offline: `--no-verify`, so results never depend on network access) |
| `make check-migrations` | Fails if models and migrations diverge |
| `make check-no-auth-tables` | Fails if Django's default `auth_user` tables exist |
| `make schema` | Regenerates `docs/api/openapi.yaml` |
| `make schema-check` | Fails if the committed schema differs from the generated one |
| `make deploy-check` | `manage.py check --deploy` against production settings |
| `make qa` | Every local quality gate |

## API

The REST API is versioned by URL path: `/api/v1/`. Conventions (details in the ADRs):

- **JSON only**: requests are parsed as JSON (`415` otherwise); responses are JSON; datetimes
  are ISO 8601 UTC.
- **Deny by default**: an endpoint without explicit permissions is unreachable. Public endpoints
  use `PublicEndpoint` **and** must be listed in `API_PUBLIC_ENDPOINTS`. Every DRF view uses
  the project base classes (`AemsAPIView` and others), whose runtime guard refuses unauthenticated
  access to any non-allowlisted endpoint. System checks `core.E001`–`core.E005` catch
  misconfiguration at startup ([ADR-0012](docs/adr/0012-api-access-control-enforcement.md)).
  Every other endpoint requires a valid access token; unauthenticated requests receive
  `401 not_authenticated` with `WWW-Authenticate: Bearer realm="api"`.
- **Errors**: RFC 9457 Problem Details (`application/problem+json`) with a stable `code` and the
  `request_id` ([ADR-0009](docs/adr/0009-api-error-response-conventions.md)). `WWW-Authenticate`,
  `Retry-After` and `Allow` headers are preserved.
- **Request IDs**: every response carries `X-Request-ID`. A valid client-supplied ID (8–128
  characters of `A-Z a-z 0-9 . _ : -`) is propagated; otherwise a UUIDv4 is generated
  ([ADR-0010](docs/adr/0010-request-correlation-and-structured-logging.md)).
- **Pagination**: `?page=` and `?page_size=` (default 25, maximum 100; larger values are capped).
  Responses contain `count`, `page`, `page_size`, `total_pages`, `next`, `previous` and `results`.
  An invalid value returns `400 invalid_query_parameters`; a page past the end returns
  `404 page_not_found`.
- **Filtering and ordering**: only explicitly allowlisted fields. An unknown `?ordering=` field
  returns 400. Ordering always ends with the primary key, so pages are stable.

| Endpoint | Description | Access |
|---|---|---|
| `GET /api/v1/` | API root (service name and API version) | Public |
| `/api/v1/auth/...` | Authentication, profile, passwords and sessions (see below) | Mixed |
| `GET /api/schema/` | OpenAPI 3 schema | Public when `API_DOCS_ENABLED`; always 404 in production |
| `GET /api/docs/`, `GET /api/redoc/` | Swagger UI / ReDoc | Same as above |

The committed contract lives at [`docs/api/openapi.yaml`](docs/api/openapi.yaml). Regenerate it
with `make schema`; CI fails if it is stale.

## Authentication

Design: [ADR-0004](docs/adr/0004-authentication-and-session-management.md) and
[ADR-0013](docs/adr/0013-authentication-implementation-and-security-events.md).

- **Access token**: a JWT valid for 10 minutes, returned in the JSON body and sent as
  `Authorization: Bearer <token>`. Clients keep it in memory only, never in
  `localStorage`/`sessionStorage`.
- **Refresh token**: kept only in the `aems_refresh` cookie (`HttpOnly`, `Secure`,
  `SameSite=Strict`, `Path=/api/v1/auth/`). It is never in a response body. It lasts 7 days and is
  rotated on every refresh; each sign-in session has an absolute lifetime of 30 days.
- **Server-side sessions**: each sign-in creates an `AuthSession`. Every request checks that the
  session and user are still valid, so logout, password changes, deactivation and replay detection
  take effect **immediately**. Reusing an already-rotated refresh token revokes the whole session.
- **CSRF**: cookie-authenticated calls (refresh, and logout with the cookie) require the
  `X-CSRFToken` header (the `csrftoken` cookie value from `GET /api/v1/auth/csrf/`) and a
  same-origin `Origin`/`Referer`.
- **Abuse protection**: atomic PostgreSQL rate limits per IP and account, plus a temporary
  exponential lockout after repeated failures. Responses never reveal whether an account exists.

| Endpoint | Purpose | Access |
|---|---|---|
| `GET /api/v1/auth/csrf/` | Set the CSRF cookie | Public |
| `POST /api/v1/auth/login/` | Sign in (`email`, `password`) → access token + refresh cookie | Public |
| `POST /api/v1/auth/token/refresh/` | Rotate the refresh cookie → new access token | Refresh cookie + CSRF |
| `POST /api/v1/auth/logout/` | Revoke the current session, clear the cookie | Refresh cookie + CSRF, or bearer |
| `GET`, `PATCH /api/v1/auth/me/` | Own profile (only `full_name` is editable) | Bearer |
| `POST /api/v1/auth/password/change/` | Change password; revokes all sessions, returns new tokens | Bearer |
| `POST /api/v1/auth/password/reset/` | Email a reset link (always `202`) | Public |
| `POST /api/v1/auth/password/reset/confirm/` | Set a new password (`uid`, `token`, `new_password`) | Public |
| `GET /api/v1/auth/sessions/` | List own active sessions | Bearer |
| `DELETE /api/v1/auth/sessions/{id}/` | Revoke one own session | Bearer |
| `POST /api/v1/auth/sessions/revoke-others/` | Revoke all own sessions except the current one | Bearer |

There is no self-service registration. Accounts are created by platform administrators (and, from
Batch 7, through organization invitations). Password-reset emails are delivered through `EMAIL_URL`
(Mailpit locally: http://localhost:8025/). The reset link carries its token in the URL fragment.
A `202` means the request was accepted, **not** that an email was delivered: it is sent synchronously
and not retried, and transport failures are logged (`auth.password_reset.delivery_failed`, without
the address or token) while the response stays identical, so it cannot reveal whether an account
exists. Response *time* is not constant, because a known account waits for the mail server
(see ADR-0013).
Expired rate-limit records can be removed with `python manage.py purge_auth_rate_limits`.

## Health endpoints

| Endpoint | Meaning | Checks |
|---|---|---|
| `GET /health/live/` | Process is up | none (never touches dependencies) |
| `GET /health/ready/` | Ready to serve traffic | PostgreSQL `SELECT 1`; returns `503` if unavailable |

Responses are uncached and never include internal error details.

## Configuration

All configuration comes from environment variables (see [`.env.example`](.env.example)).

| Variable | Default | Purpose |
|---|---|---|
| `DJANGO_LOG_FORMAT` | `json` (`console` in local settings) | Log rendering |
| `DJANGO_LOG_LEVEL` | `INFO` | Root log level (SQL logging is always suppressed) |
| `DJANGO_API_DOCS_ENABLED` | `false` (`true` in local settings) | Serve schema/Swagger/ReDoc; production refuses `true` |
| `DJANGO_CORS_ALLOWED_ORIGINS` | none (`http://localhost:3000` locally) | Explicit origin allowlist; no wildcards; HTTPS required in production |
| `DJANGO_CORS_ALLOW_CREDENTIALS` | `false` | Cross-origin cookies (set `true` when the frontend runs on another origin) |
| `DJANGO_JWT_SIGNING_KEY` | — (required) | Dedicated JWT signing key; production requires 50+ random characters, different from `DJANGO_SECRET_KEY` |
| `DJANGO_JWT_ISSUER` / `DJANGO_JWT_AUDIENCE` | unset | Optional `iss`/`aud` claims, enforced when set |
| `DJANGO_PASSWORD_MIN_LENGTH` | `12` | Minimum password length (production refuses less than 12) |
| `DJANGO_PASSWORD_RESET_TIMEOUT` | `3600` | Reset-link lifetime in seconds |
| `AEMS_FRONTEND_BASE_URL` | `http://localhost:3000` | Base URL used in password-reset links |
| `DJANGO_AUTH_REFRESH_COOKIE_SECURE` | `true` (`false` in local settings) | Secure flag on the refresh cookie (production requires `true`) |
| `DJANGO_TRUSTED_PROXY_COUNT` | `0` | Number of trusted reverse proxies whose `X-Forwarded-For` entry is used as the client IP |
| `DJANGO_ADMIN_URL` | `admin/` | Path of the staff-only admin |

Every environment refuses to start unless `DATABASE_URL` resolves to the PostgreSQL backend
(`postgres://`, `postgresql://`, or `pgsql://`); SQLite and other engines are rejected.

### Production configuration

`config.settings.production` refuses to start when:

- `DJANGO_DEBUG` is true (it is validated, never silently overridden);
- `DJANGO_SECRET_KEY` is missing, shorter than 50 characters, low-variety, or a placeholder;
- `DJANGO_ALLOWED_HOSTS` is empty or contains `*`;
- `DJANGO_API_DOCS_ENABLED` is true;
- a CORS origin is a wildcard, `null`, malformed, or not HTTPS;
- `DJANGO_JWT_SIGNING_KEY` is missing, weak, a placeholder, or equal to `DJANGO_SECRET_KEY`;
- the refresh cookie is not `Secure`, or `DJANGO_PASSWORD_MIN_LENGTH` is below 12.

**Trusted TLS proxy (`DJANGO_BEHIND_TLS_PROXY`, default `false`).** When enabled, Django treats a
request as HTTPS if it carries `X-Forwarded-Proto: https`. Enable it **only** when every request
reaches Django through a trusted TLS-terminating reverse proxy (load balancer, ingress) that
**removes any client-supplied `X-Forwarded-Proto` header and overwrites it** with the scheme it
actually received, and when Django is not reachable any other way. Otherwise clients could forge
the header and plain-HTTP requests would be treated as secure.

**Container health check.** The production image's `HEALTHCHECK` runs
[`scripts/healthcheck.py`](backend/scripts/healthcheck.py), which calls `/health/live/` on the
local socket while sending the first `DJANGO_ALLOWED_HOSTS` entry as the `Host` header. Host
validation therefore stays fully enforced: no loopback address or wildcard needs to be added to
`ALLOWED_HOSTS`.

The application connects to PostgreSQL as a non-superuser role (`aems_app`) created by
[`docker/postgres/init/01-create-app-role.sh`](docker/postgres/init/01-create-app-role.sh).

## Continuous integration

[Backend CI](.github/workflows/backend-ci.yml) runs on every pull request to `main` and every
push to `main`, with no path filters ([ADR-0011](docs/adr/0011-continuous-integration.md)):

| Check | Contents |
|---|---|
| Lint & type check | ruff, ruff format, strict mypy, hygiene hooks |
| Tests & migrations | PostgreSQL 17, non-superuser role, fresh migrate, no default auth tables, migration drift, full suite with 90% branch coverage, coverage artifact |
| Security | Bandit, pip-audit, detect-secrets, production `check --deploy` |
| API contract | OpenAPI generation, validation and drift check |
| Docker image | clean build of the committed Dockerfile, non-root, container becomes `healthy`, endpoint behaviour |
| Backend CI result | passes only if every job above passed (recommended required check) |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Copyright (c) 2026 Rahil Ashraf. All rights reserved.

AEMS is publicly available for portfolio demonstration and educational reference. Public
availability does not grant permission to reuse, redistribute, modify, or commercially exploit the
source code. See [LICENSE](LICENSE) for details.

Third-party dependencies are licensed separately under their own terms, which this notice does not
replace or modify.
