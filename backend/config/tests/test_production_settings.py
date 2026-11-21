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
    " settings.SESSION_COOKIE_SECURE, settings.CSRF_COOKIE_SECURE)\n"
)


def _run(**overrides: str) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        # Propagate coverage.py subprocess measurement settings, nothing else.
        **{k: v for k, v in os.environ.items() if k.startswith("COVERAGE_")},
        "DJANGO_SETTINGS_MODULE": "config.settings.production",
        "DJANGO_SECRET_KEY": STRONG_KEY,
        "DJANGO_ALLOWED_HOSTS": "api.example.org",
        "DATABASE_URL": "postgres://u:p@localhost:5432/db",
        **overrides,
    }
    return subprocess.run(
        [sys.executable, "-c", SCRIPT],
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
    assert result.stdout.split() == ["False", "True", "31536000", "True", "True"]


def test_production_ignores_debug_flag_from_environment() -> None:
    result = _run(DJANGO_DEBUG="true")

    assert result.returncode == 0, result.stderr
    assert result.stdout.split()[0] == "False"


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
    result = _run(**overrides)

    assert result.returncode != 0
    assert "ImproperlyConfigured" in result.stderr
    assert message in result.stderr


def test_production_requires_secret_key() -> None:
    env_without_key = {"DJANGO_SECRET_KEY": ""}
    result = _run(**env_without_key)

    assert result.returncode != 0
    assert "ImproperlyConfigured" in result.stderr
