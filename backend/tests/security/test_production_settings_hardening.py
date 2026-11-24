"""Production configuration hardening (plan §8, ADR-0019).

Complements ``config/tests/test_production_settings.py`` with the Batch 8 checks:

- AEMS-023: production accepted the console/file/in-memory email backends (one-time links printed
  to logs or files while the outbox recorded them as delivered) and unencrypted SMTP.
- AEMS-026: production accepted plain-HTTP and wildcard ``CSRF_TRUSTED_ORIGINS``.
- Every security-relevant production setting, asserted in one snapshot.
- ``check --deploy`` fails for weakened transport settings.
"""

import json
import os
import subprocess
import sys

import pytest

from config.tests.test_production_settings import BACKEND_DIR, _run

SNAPSHOT = (
    "import django, json\n"
    "from django.conf import settings as s\n"
    "django.setup()\n"
    "print(json.dumps({\n"
    " 'DEBUG': s.DEBUG, 'SECURE_SSL_REDIRECT': s.SECURE_SSL_REDIRECT,\n"
    " 'SECURE_HSTS_SECONDS': s.SECURE_HSTS_SECONDS,\n"
    " 'SECURE_HSTS_INCLUDE_SUBDOMAINS': s.SECURE_HSTS_INCLUDE_SUBDOMAINS,\n"
    " 'SECURE_HSTS_PRELOAD': s.SECURE_HSTS_PRELOAD,\n"
    " 'SESSION_COOKIE_SECURE': s.SESSION_COOKIE_SECURE,\n"
    " 'SESSION_COOKIE_HTTPONLY': s.SESSION_COOKIE_HTTPONLY,\n"
    " 'SESSION_COOKIE_SAMESITE': s.SESSION_COOKIE_SAMESITE,\n"
    " 'CSRF_COOKIE_SECURE': s.CSRF_COOKIE_SECURE, 'CSRF_COOKIE_SAMESITE': s.CSRF_COOKIE_SAMESITE,\n"
    " 'X_FRAME_OPTIONS': s.X_FRAME_OPTIONS,\n"
    " 'SECURE_CONTENT_TYPE_NOSNIFF': s.SECURE_CONTENT_TYPE_NOSNIFF,\n"
    " 'SECURE_REFERRER_POLICY': s.SECURE_REFERRER_POLICY,\n"
    " 'SECURE_CROSS_ORIGIN_OPENER_POLICY': s.SECURE_CROSS_ORIGIN_OPENER_POLICY,\n"
    " 'CORS_ALLOW_ALL_ORIGINS': s.CORS_ALLOW_ALL_ORIGINS,\n"
    " 'CORS_ALLOWED_ORIGINS': s.CORS_ALLOWED_ORIGINS,\n"
    " 'CSRF_TRUSTED_ORIGINS': s.CSRF_TRUSTED_ORIGINS,\n"
    " 'SECURE_PROXY_SSL_HEADER': s.SECURE_PROXY_SSL_HEADER,\n"
    " 'TRUSTED_PROXY_COUNT': s.TRUSTED_PROXY_COUNT,\n"
    " 'DATA_UPLOAD_MAX_MEMORY_SIZE': s.DATA_UPLOAD_MAX_MEMORY_SIZE,\n"
    " 'FILE_UPLOAD_MAX_MEMORY_SIZE': s.FILE_UPLOAD_MAX_MEMORY_SIZE,\n"
    " 'API_DOCS_ENABLED': s.API_DOCS_ENABLED,\n"
    " 'REFRESH_COOKIE': {k: s.AUTH_REFRESH_COOKIE[k] for k in ('SECURE', 'SAMESITE', 'PATH')},\n"
    " 'ATOMIC_REQUESTS': s.DATABASES['default']['ATOMIC_REQUESTS'],\n"
    " 'EMAIL_BACKEND': s.EMAIL_BACKEND, 'EMAIL_USE_TLS': s.EMAIL_USE_TLS,\n"
    " 'JWT_ALGORITHM': s.SIMPLE_JWT['ALGORITHM'], 'JWT_LEEWAY': s.SIMPLE_JWT['LEEWAY'],\n"
    " 'PASSWORD_HASHER': s.PASSWORD_HASHERS[0],\n"
    " 'PARSERS': s.REST_FRAMEWORK['DEFAULT_PARSER_CLASSES'],\n"
    " 'LOG_FORMAT': s.LOG_FORMAT,\n"
    "}))\n"
)


def test_production_security_settings_snapshot() -> None:
    result = _run(SNAPSHOT, overrides={"DJANGO_CSRF_TRUSTED_ORIGINS": "https://app.example.org"})
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "DEBUG": False,
        "SECURE_SSL_REDIRECT": True,
        "SECURE_HSTS_SECONDS": 31_536_000,
        "SECURE_HSTS_INCLUDE_SUBDOMAINS": True,
        "SECURE_HSTS_PRELOAD": True,
        "SESSION_COOKIE_SECURE": True,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Strict",
        "CSRF_COOKIE_SECURE": True,
        "CSRF_COOKIE_SAMESITE": "Strict",
        "X_FRAME_OPTIONS": "DENY",
        "SECURE_CONTENT_TYPE_NOSNIFF": True,
        "SECURE_REFERRER_POLICY": "strict-origin-when-cross-origin",
        "SECURE_CROSS_ORIGIN_OPENER_POLICY": "same-origin",
        "CORS_ALLOW_ALL_ORIGINS": False,
        "CORS_ALLOWED_ORIGINS": [],
        "CSRF_TRUSTED_ORIGINS": ["https://app.example.org"],
        "SECURE_PROXY_SSL_HEADER": None,  # proxy headers untrusted unless opted in
        "TRUSTED_PROXY_COUNT": 0,  # X-Forwarded-For untrusted unless configured
        "DATA_UPLOAD_MAX_MEMORY_SIZE": 2_621_440,
        "FILE_UPLOAD_MAX_MEMORY_SIZE": 2_621_440,
        "API_DOCS_ENABLED": False,
        "REFRESH_COOKIE": {"SECURE": True, "SAMESITE": "Strict", "PATH": "/api/v1/auth/"},
        "ATOMIC_REQUESTS": False,
        "EMAIL_BACKEND": "django.core.mail.backends.smtp.EmailBackend",
        "EMAIL_USE_TLS": True,
        "JWT_ALGORITHM": "HS256",
        "JWT_LEEWAY": 0,
        "PASSWORD_HASHER": "django.contrib.auth.hashers.Argon2PasswordHasher",
        "PARSERS": ["apps.core.api.parsers.BoundedJSONParser"],
        "LOG_FORMAT": "json",
    }


# ------------------------------------------------------------------------------- AEMS-023
@pytest.mark.parametrize(
    "email_url",
    [
        "consolemail://",
        "filemail:///tmp/mail",
        "memorymail://",
        "dummymail://",
        "smtp://mail.example.org:25",
    ],
)
def test_unsafe_email_configuration_is_refused(email_url: str) -> None:
    result = _run(overrides={"EMAIL_URL": email_url})
    assert result.returncode != 0
    assert "EMAIL_URL must" in result.stderr


def test_missing_email_url_is_refused() -> None:
    result = _run(unset=("EMAIL_URL",))
    assert result.returncode != 0
    assert "EMAIL_URL must configure SMTP in production" in result.stderr


@pytest.mark.parametrize(
    "email_url", ["smtp+tls://mail.example.org:587", "smtps://mail.example.org:587"]
)
def test_encrypted_smtp_is_accepted(email_url: str) -> None:
    assert _run(overrides={"EMAIL_URL": email_url}).returncode == 0


def test_unencrypted_smtp_requires_an_explicit_opt_in() -> None:
    result = _run(
        overrides={
            "EMAIL_URL": "smtp://mailpit:1025",
            "AEMS_EMAIL_ALLOW_UNENCRYPTED_SMTP": "true",
        }
    )
    assert result.returncode == 0, result.stderr


def test_opt_in_never_allows_non_smtp_backends() -> None:
    result = _run(
        overrides={"EMAIL_URL": "consolemail://", "AEMS_EMAIL_ALLOW_UNENCRYPTED_SMTP": "true"}
    )
    assert result.returncode != 0


# ------------------------------------------------------------------------------- AEMS-026
@pytest.mark.parametrize(
    "origins",
    [
        "http://app.example.org",
        "https://*.example.org",
        "https://app.example.org/path",
        "app.example.org",
        "https://app.example.org,http://localhost:3000",
    ],
)
def test_unsafe_csrf_trusted_origins_are_refused(origins: str) -> None:
    result = _run(overrides={"DJANGO_CSRF_TRUSTED_ORIGINS": origins})
    assert result.returncode != 0
    assert "CSRF trusted origin" in result.stderr


def test_https_csrf_trusted_origins_are_accepted() -> None:
    result = _run(
        overrides={
            "DJANGO_CSRF_TRUSTED_ORIGINS": "https://app.example.org,https://admin.example.org"
        }
    )
    assert result.returncode == 0, result.stderr


# ------------------------------------------------------------------------------- deploy check
def _deploy_check(**overrides: str) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        **{k: v for k, v in os.environ.items() if k.startswith("COVERAGE_")},
        "DJANGO_SETTINGS_MODULE": "config.settings.production",
        "DJANGO_SECRET_KEY": "k3J9#vQ2!mZ8@xL5$wR7%tY1^pN4&bH6*cF0(gD3)sA9-eU2+iO8=jK5_lM7~nB1",
        "DJANGO_JWT_SIGNING_KEY": "p8V#q2Lm!x7Rz4@kT9w$Hn3^bY6&cJ1*dF5(gS0)aE8-uI2+oP7=lK4_mN9~vB3",
        "DJANGO_ALLOWED_HOSTS": "api.example.org",
        "AEMS_FRONTEND_BASE_URL": "https://app.example.org",
        "DATABASE_URL": "postgres://u:p@localhost:5432/db",
        "EMAIL_URL": "smtp+tls://mail.example.org:587",
        **overrides,
    }
    return subprocess.run(
        [sys.executable, "manage.py", "check", "--deploy", "--fail-level", "WARNING"],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def test_deploy_check_passes_for_the_hardened_configuration() -> None:
    result = _deploy_check()
    assert result.returncode == 0, result.stderr + result.stdout


@pytest.mark.parametrize(
    ("overrides", "warning"),
    [
        ({"DJANGO_SECURE_HSTS_SECONDS": "0"}, "security.W004"),
        ({"DJANGO_SECURE_SSL_REDIRECT": "false"}, "security.W008"),
    ],
)
def test_deploy_check_fails_for_weakened_transport(overrides: dict[str, str], warning: str) -> None:
    result = _deploy_check(**overrides)
    assert result.returncode != 0
    assert warning in result.stderr + result.stdout
