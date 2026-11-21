"""Import the production settings module in a clean subprocess with controlled environments.

A subprocess is used because Django settings are evaluated once per process.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[2]
STRONG_KEY = "k3J9#vQ2!mZ8@xL5$wR7%tY1^pN4&bH6*cF0(gD3)sA9-eU2+iO8=jK5_lM7~nB1"
SCRIPT = (
    "import django\n"
    "from django.conf import settings\n"
    "django.setup()\n"
    "print(settings.DEBUG, settings.SECURE_SSL_REDIRECT, settings.SECURE_HSTS_SECONDS,"
    " settings.SESSION_COOKIE_SECURE, settings.CSRF_COOKIE_SECURE,"
    " settings.DATABASES['default']['ENGINE'])\n"
)
PROXY_SCRIPT = (
    "import django\n"
    "from django.conf import settings\n"
    "django.setup()\n"
    "print(repr(settings.SECURE_PROXY_SSL_HEADER))\n"
)


def _run(
    script: str = SCRIPT,
    *,
    overrides: dict[str, str] | None = None,
    unset: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        # Propagate coverage.py subprocess measurement settings, nothing else.
        **{k: v for k, v in os.environ.items() if k.startswith("COVERAGE_")},
        "DJANGO_SETTINGS_MODULE": "config.settings.production",
        "DJANGO_SECRET_KEY": STRONG_KEY,
        "DJANGO_ALLOWED_HOSTS": "api.example.org",
        "DATABASE_URL": "postgres://u:p@localhost:5432/db",
        **(overrides or {}),
    }
    for name in unset:
        env.pop(name, None)
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def test_production_settings_load_with_safe_environment() -> None:
    result = _run()

    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == [
        "False",
        "True",
        "31536000",
        "True",
        "True",
        "django.db.backends.postgresql",
    ]


@pytest.mark.parametrize("value", ["false", "False", "0", "off"])
def test_production_accepts_explicitly_disabled_debug(value: str) -> None:
    result = _run(overrides={"DJANGO_DEBUG": value})

    assert result.returncode == 0, result.stderr
    assert result.stdout.split()[0] == "False"


@pytest.mark.parametrize("value", ["true", "True", "1", "on", "yes"])
def test_production_refuses_to_start_with_debug_enabled(value: str) -> None:
    """Regression (AEMS-001): DJANGO_DEBUG=true must fail startup, not be silently ignored."""
    result = _run(overrides={"DJANGO_DEBUG": value})

    assert result.returncode != 0
    assert "ImproperlyConfigured" in result.stderr
    assert "DJANGO_DEBUG must be false in production" in result.stderr


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"DJANGO_SECRET_KEY": "django-insecure-" + STRONG_KEY}, "placeholder"),
        ({"DJANGO_SECRET_KEY": "too-short"}, "at least 50"),
        ({"DJANGO_ALLOWED_HOSTS": ""}, "must be set"),
        ({"DJANGO_ALLOWED_HOSTS": "*"}, "must not contain"),
    ],
)
def test_production_refuses_unsafe_environment(overrides: dict[str, str], message: str) -> None:
    result = _run(overrides=overrides)

    assert result.returncode != 0
    assert "ImproperlyConfigured" in result.stderr
    assert message in result.stderr


def test_production_requires_secret_key() -> None:
    result = _run(unset=("DJANGO_SECRET_KEY",))

    assert result.returncode != 0
    assert "ImproperlyConfigured" in result.stderr
    assert "DJANGO_SECRET_KEY" in result.stderr


class TestTrustedTlsProxy:
    """Regression (AEMS-002): forwarded-protocol trust is opt-in."""

    def test_not_trusted_by_default(self) -> None:
        result = _run(PROXY_SCRIPT, unset=("DJANGO_BEHIND_TLS_PROXY",))

        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "None"

    @pytest.mark.parametrize("value", ["false", "0"])
    def test_not_trusted_when_explicitly_disabled(self, value: str) -> None:
        result = _run(PROXY_SCRIPT, overrides={"DJANGO_BEHIND_TLS_PROXY": value})

        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "None"

    @pytest.mark.parametrize("value", ["true", "1"])
    def test_trusted_when_explicitly_enabled(self, value: str) -> None:
        result = _run(PROXY_SCRIPT, overrides={"DJANGO_BEHIND_TLS_PROXY": value})

        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "('HTTP_X_FORWARDED_PROTO', 'https')"


class TestDatabaseEngineEnforcement:
    """Regression (AEMS-004): only PostgreSQL is accepted at startup."""

    @pytest.mark.parametrize(
        "url",
        [
            "postgres://u:p@localhost:5432/db",
            "postgresql://u:p@localhost:5432/db",
            "pgsql://u:p@localhost:5432/db",
        ],
    )
    def test_accepts_postgresql_urls(self, url: str) -> None:
        result = _run(overrides={"DATABASE_URL": url})

        assert result.returncode == 0, result.stderr
        assert result.stdout.split()[-1] == "django.db.backends.postgresql"

    @pytest.mark.parametrize(
        "url",
        [
            "sqlite:///db.sqlite3",
            "sqlite://:memory:",
            "mysql://u:p@localhost:3306/db",
            "oracle://u:p@localhost:1521/db",
            "postgis://u:p@localhost:5432/db",
        ],
    )
    def test_rejects_unsupported_engines(self, url: str) -> None:
        result = _run(overrides={"DATABASE_URL": url})

        assert result.returncode != 0
        assert "ImproperlyConfigured" in result.stderr
        assert "Unsupported database engine" in result.stderr
