# syntax=docker/dockerfile:1.7
# AEMS backend image. Targets:
#   dev  — development tooling, used by docker-compose (source bind-mounted)
#   prod — minimal runtime, non-root, gunicorn (built in CI; not deployed in Phase 1)

ARG PYTHON_VERSION=3.13

# ---------------------------------------------------------------- base
FROM python:${PYTHON_VERSION}-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PATH="/opt/venv/bin:${PATH}"

# uv is installed from PyPI (pinned) so the build only needs PyPI access.
RUN pip install "uv==0.11.32"

WORKDIR /app

# ---------------------------------------------------------------- dev
FROM base AS dev

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project

COPY . .

EXPOSE 8000
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

# ---------------------------------------------------------------- prod
FROM base AS prod

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev \
    && pip uninstall --yes uv

RUN groupadd --system --gid 10001 aems \
    && useradd --system --uid 10001 --gid aems --no-create-home --shell /usr/sbin/nologin aems

COPY --chown=aems:aems . .

USER aems:aems

ENV DJANGO_SETTINGS_MODULE=config.settings.production
EXPOSE 8000

# Probes the local socket while presenting the first DJANGO_ALLOWED_HOSTS entry as the Host
# header, so Django host validation applies unchanged (see scripts/healthcheck.py).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-m", "scripts.healthcheck"]

CMD ["gunicorn", "config.wsgi:application", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "3", \
     "--access-logfile", "-", \
     "--forwarded-allow-ips", "127.0.0.1"]
