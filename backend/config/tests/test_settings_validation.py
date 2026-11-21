import pytest
from django.core.exceptions import ImproperlyConfigured

from config.settings.validation import (
    validate_database_engine,
    validate_production_settings,
    validate_secret_key,
)

STRONG_KEY = "k3J9#vQ2!mZ8@xL5$wR7%tY1^pN4&bH6*cF0(gD3)sA9-eU2+iO8=jK5_lM7~nB1"
HOSTS = ["api.example.org"]


class TestValidateSecretKey:
    def test_accepts_strong_random_key(self) -> None:
        validate_secret_key(STRONG_KEY)

    def test_rejects_short_key(self) -> None:
        with pytest.raises(ImproperlyConfigured, match="at least 50"):
            validate_secret_key("short")

    def test_rejects_low_variety_key(self) -> None:
        with pytest.raises(ImproperlyConfigured, match="variety"):
            validate_secret_key("a" * 64)

    @pytest.mark.parametrize(
        "key",
        [
            "django-insecure-" + STRONG_KEY,
            "test-only-insecure-secret-key-not-for-production-xxxxxxxxxxxxx",
            "change-me-" + STRONG_KEY,
            "dev-only-" + STRONG_KEY,
        ],
    )
    def test_rejects_placeholder_keys(self, key: str) -> None:
        with pytest.raises(ImproperlyConfigured, match="placeholder"):
            validate_secret_key(key)


class TestValidateProductionSettings:
    def test_accepts_safe_configuration(self) -> None:
        validate_production_settings(secret_key=STRONG_KEY, debug=False, allowed_hosts=HOSTS)

    def test_rejects_debug(self) -> None:
        with pytest.raises(ImproperlyConfigured, match="DEBUG"):
            validate_production_settings(secret_key=STRONG_KEY, debug=True, allowed_hosts=HOSTS)

    def test_rejects_missing_allowed_hosts(self) -> None:
        with pytest.raises(ImproperlyConfigured, match="must be set"):
            validate_production_settings(secret_key=STRONG_KEY, debug=False, allowed_hosts=[])

    def test_rejects_wildcard_allowed_hosts(self) -> None:
        with pytest.raises(ImproperlyConfigured, match=r"'\*'"):
            validate_production_settings(
                secret_key=STRONG_KEY, debug=False, allowed_hosts=["*", "api.example.org"]
            )


class TestValidateDatabaseEngine:
    def test_accepts_postgresql(self) -> None:
        validate_database_engine("django.db.backends.postgresql")

    @pytest.mark.parametrize(
        "engine",
        [
            "django.db.backends.sqlite3",
            "django.db.backends.mysql",
            "django.db.backends.oracle",
            "django.contrib.gis.db.backends.postgis",
            "",
        ],
    )
    def test_rejects_other_engines(self, engine: str) -> None:
        with pytest.raises(ImproperlyConfigured, match="Unsupported database engine"):
            validate_database_engine(engine)
