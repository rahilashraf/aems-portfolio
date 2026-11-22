import os
import subprocess
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]


def _run_local(database_url: str) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        # Propagate coverage.py subprocess measurement settings, nothing else.
        **{k: v for k, v in os.environ.items() if k.startswith("COVERAGE_")},
        "DJANGO_SETTINGS_MODULE": "config.settings.local",
        "DJANGO_SECRET_KEY": "local-development-key",
        "DJANGO_JWT_SIGNING_KEY": "local-development-jwt-key",
        "DATABASE_URL": database_url,
    }
    script = (
        "import django\nfrom django.conf import settings\ndjango.setup()\n"
        "print(settings.DEBUG, ','.join(settings.ALLOWED_HOSTS))\n"
    )
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def test_local_settings_default_to_debug_with_loopback_hosts() -> None:
    result = _run_local("postgres://u:p@localhost:5432/db")

    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["True", "localhost,127.0.0.1"]


def test_local_settings_reject_sqlite() -> None:
    """Regression (AEMS-004): engine enforcement applies to every environment, not only prod."""
    result = _run_local("sqlite:///db.sqlite3")

    assert result.returncode != 0
    assert "Unsupported database engine" in result.stderr
