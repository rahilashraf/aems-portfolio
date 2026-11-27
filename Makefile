# AEMS developer commands. Run `make help` for a list.
#
# Host targets use uv in backend/ (fast feedback); `docker-*` targets run inside the compose stack.

SHELL := /bin/bash
# Every recipe line runs with errexit, nounset and pipefail, so a failure anywhere in a
# pipeline (e.g. the dependency export feeding pip-audit) fails the target.
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

# Load local development variables (if present) for host-side commands. Each .env value is only a
# default (?=): variables already set in the environment or on the command line take precedence,
# e.g. `DATABASE_URL=... make migrate` really targets that database.
ENV_FILE_VARS := $(shell sed -n 's/^\([A-Z_][A-Z0-9_]*\)=.*/\1/p' .env 2>/dev/null)
$(foreach var,$(ENV_FILE_VARS),$(eval $(var) ?= $(shell sed -n 's/^$(var)=//p' .env)))
export $(ENV_FILE_VARS)

BACKEND := backend
UV := uv --directory $(BACKEND)
COMPOSE := docker compose
MANAGE := $(UV) run python manage.py

# Two database roles (ADR-0016): migrations, drift checks and the test suite connect as the
# owner (DATABASE_OWNER_URL); everything else uses DATABASE_URL, the runtime role.
OWNER_DATABASE_URL = $(or $(DATABASE_OWNER_URL),$(DATABASE_URL))
AS_OWNER = DATABASE_URL="$(OWNER_DATABASE_URL)"

.PHONY: help
help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ------------------------------------------------------------------ setup
.PHONY: env install hooks
env: ## Create .env from .env.example if missing
	@test -f .env || (cp .env.example .env && echo "Created .env — review the values.")

install: ## Install backend dependencies (incl. dev tools) from the lockfile
	$(UV) sync --frozen

hooks: install ## Install pre-commit git hooks
	uv run --project $(BACKEND) pre-commit install

# ------------------------------------------------------------------ docker stack
.PHONY: up down build logs ps docker-shell docker-test docker-migrate
up: env ## Start db, backend and mailpit in the background
	$(COMPOSE) up -d --build

down: ## Stop the stack (data volume is kept)
	$(COMPOSE) down

build: ## Build the backend dev image
	$(COMPOSE) build backend

logs: ## Follow logs from all services
	$(COMPOSE) logs -f

ps: ## Show service status
	$(COMPOSE) ps

docker-shell: ## Open a shell in the backend container
	$(COMPOSE) exec backend bash

docker-test: ## Run the test suite inside the backend container (as the owner role)
	$(COMPOSE) exec -e DJANGO_SETTINGS_MODULE=config.settings.test backend \
		sh -c 'AEMS_RUNTIME_DATABASE_URL="$$DATABASE_URL" DATABASE_URL="$$DATABASE_OWNER_URL" pytest --cov'

docker-migrate: ## Apply migrations inside the backend container (as the owner role)
	$(COMPOSE) exec backend sh -c 'DATABASE_URL="$$DATABASE_OWNER_URL" python manage.py migrate'

# ------------------------------------------------------------------ django (host)
.PHONY: run migrate makemigrations check check-migrations check-no-auth-tables \
	verify-runtime-privileges shell sendtestemail docker-sendtestemail \
	deliver-reset-emails docker-deliver-reset-emails
run: ## Run the dev server on the host (needs the compose db running)
	$(MANAGE) runserver

migrate: ## Apply migrations as the owner role; grants the runtime role its privileges (host)
	$(AS_OWNER) $(MANAGE) migrate

makemigrations: ## Create migrations (host)
	$(AS_OWNER) $(MANAGE) makemigrations

check: ## Django system checks (incl. the public-endpoint allowlist)
	$(MANAGE) check --fail-level WARNING

check-migrations: ## Fail if models and migrations are out of sync
	$(AS_OWNER) $(MANAGE) makemigrations --check --dry-run

check-no-auth-tables: ## Fail if Django's default auth/admin/session tables exist in the database
	$(MANAGE) verify_no_default_tables

verify-runtime-privileges: ## Fail unless DATABASE_URL's role can only read/append the audit log
	$(MANAGE) verify_runtime_privileges

shell: ## Django shell (host)
	$(MANAGE) shell

TEST_EMAIL ?= dev@example.test

sendtestemail: ## Send a test email via EMAIL_URL (host); view it in Mailpit
	$(MANAGE) sendtestemail $(TEST_EMAIL)

docker-sendtestemail: ## Send a test email from the backend container to Mailpit
	$(COMPOSE) exec backend python manage.py sendtestemail $(TEST_EMAIL)

deliver-reset-emails: ## Send queued password-reset emails (host); view them in Mailpit
	$(MANAGE) deliver_password_reset_emails

docker-deliver-reset-emails: ## Send queued password-reset emails from the backend container
	$(COMPOSE) exec backend python manage.py deliver_password_reset_emails

# ------------------------------------------------------------------ quality (host)
.PHONY: test lint format typecheck audit security secrets deploy-check schema schema-check qa
PYTEST_ARGS ?=

test: ## Run tests with coverage (90% gate) as the owner role; extra args via PYTEST_ARGS
	$(AS_OWNER) AEMS_RUNTIME_DATABASE_URL="$(DATABASE_URL)" $(UV) run pytest --cov $(PYTEST_ARGS)

lint: ## Lint and check formatting
	$(UV) run ruff check .
	$(UV) run ruff format --check .

format: ## Auto-format and apply safe lint fixes
	$(UV) run ruff format .
	$(UV) run ruff check --fix .

typecheck: ## Static type checking (mypy strict)
	$(UV) run mypy .

# Overridable only so the failure-propagation behaviour can be verified (e.g. AUDIT_EXPORT=false).
AUDIT_EXPORT ?= $(UV) export --frozen --all-groups --no-emit-project --format requirements-txt

audit: ## Check dependencies for known vulnerabilities
	$(AUDIT_EXPORT) \
		| $(UV) run pip-audit --strict --disable-pip --require-hashes --requirement /dev/stdin

security: ## Static security analysis
	$(UV) run bandit -c pyproject.toml -r apps config scripts

secrets: ## Scan tracked files for committed secrets (detect-secrets baseline)
	uv run --project $(BACKEND) pre-commit run detect-secrets --all-files \
		|| { echo "--- .secrets.baseline changes made by the hook:"; \
		     git --no-pager diff -- .secrets.baseline; exit 1; }

# OpenAPI contract. Generated with the test settings so the output never depends on a local .env.
SCHEMA_FILE := docs/api/openapi.yaml
# Scratch location for the drift check (git-ignored, overwritten on each run).
SCHEMA_CHECK_FILE := backend/.schema-check/openapi.yaml
SPECTACULAR := DJANGO_SETTINGS_MODULE=config.settings.test $(UV) run python manage.py spectacular \
	--validate --fail-on-warn

schema: ## Regenerate the committed OpenAPI schema (docs/api/openapi.yaml)
	$(SPECTACULAR) --file ../$(SCHEMA_FILE)

schema-check: ## Fail if the committed OpenAPI schema differs from freshly generated output
	mkdir -p $(dir $(SCHEMA_CHECK_FILE))
	$(SPECTACULAR) --file ../$(SCHEMA_CHECK_FILE)
	diff -u $(SCHEMA_FILE) $(SCHEMA_CHECK_FILE)
	@echo "OK: $(SCHEMA_FILE) matches the generated schema"

deploy-check: ## Django deployment checklist against production settings
	DJANGO_SETTINGS_MODULE=config.settings.production DJANGO_DEBUG=false \
	DJANGO_API_DOCS_ENABLED=false DJANGO_CORS_ALLOWED_ORIGINS= DJANGO_LOG_FORMAT=json \
	DJANGO_SECRET_KEY="$$(python3 -c 'import secrets; print(secrets.token_urlsafe(64))')" \
	DJANGO_JWT_SIGNING_KEY="$$(python3 -c 'import secrets; print(secrets.token_urlsafe(64))')" \
	DJANGO_ALLOWED_HOSTS=api.example.org AEMS_FRONTEND_BASE_URL=https://app.example.org \
	DATABASE_URL=postgres://u:p@localhost:5432/db EMAIL_URL=smtp+tls://mail.example.org:587 \
	DJANGO_CSRF_TRUSTED_ORIGINS=https://app.example.org \
	$(UV) run python manage.py check --deploy --fail-level WARNING

qa: lint typecheck test security audit secrets check-migrations schema-check deploy-check ## Run every quality gate

# ------------------------------------------------------------------ frontend (FE-1A, ADR-0020)
.PHONY: fe-install fe-dev fe-lint fe-typecheck fe-test fe-build fe-browser fe-audit fe-qa
FRONTEND := frontend
PNPM := cd $(FRONTEND) && pnpm

fe-install: ## Install frontend dependencies from the lockfile (strict peer dependencies)
	$(PNPM) install --frozen-lockfile

fe-dev: ## Run the Next.js dev server with the review routes (/dev/ui, /dev/shell)
	cd $(FRONTEND) && AEMS_ENABLE_DEV_ROUTES=true pnpm dev

fe-lint: ## Prettier check and ESLint (zero warnings)
	$(PNPM) format:check
	$(PNPM) lint

fe-typecheck: ## Strict TypeScript
	$(PNPM) typecheck

fe-test: ## Unit and component tests with coverage gates
	$(PNPM) test:coverage

fe-build: ## Production build (review routes disabled)
	$(PNPM) build

fe-browser: ## Build with review routes and run the Playwright suite (set SCREENSHOTS=1 to capture)
	cd $(FRONTEND) && AEMS_ENABLE_DEV_ROUTES=true pnpm build
	cd $(FRONTEND) && E2E_DEV_ROUTES=true pnpm test:browser

fe-audit: ## Dependency vulnerability audit
	$(PNPM) audit --prod --audit-level=moderate
	$(PNPM) audit --audit-level=high

fe-qa: fe-lint fe-typecheck fe-test fe-build fe-audit ## Every frontend gate except browser tests
