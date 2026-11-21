from unittest import mock

import pytest
from django.db import OperationalError
from django.test import Client
from django.urls import reverse

LIVE = reverse("core:health-live")
READY = reverse("core:health-ready")


@pytest.fixture
def client() -> Client:
    return Client()


class TestLiveness:
    def test_returns_ok(self, client: Client) -> None:
        response = client.get(LIVE)

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_does_not_touch_database(self, client: Client) -> None:
        # No django_db marker: pytest-django raises if the view queries the database.
        assert client.get(LIVE).status_code == 200

    def test_is_not_cacheable(self, client: Client) -> None:
        response = client.get(LIVE)

        assert "no-cache" in response["Cache-Control"]
        assert "no-store" in response["Cache-Control"]

    def test_head_is_allowed(self, client: Client) -> None:
        assert client.head(LIVE).status_code == 200

    @pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
    def test_unsafe_methods_rejected(self, client: Client, method: str) -> None:
        assert getattr(client, method)(LIVE).status_code == 405


@pytest.mark.django_db
class TestReadiness:
    def test_returns_ok_when_database_reachable(self, client: Client) -> None:
        response = client.get(READY)

        assert response.status_code == 200
        assert response.json() == {"status": "ok", "checks": {"database": "ok"}}

    def test_returns_503_without_leaking_details_when_database_down(
        self, client: Client, caplog: pytest.LogCaptureFixture
    ) -> None:
        secret_detail = "could not connect to server at db-internal-host:5432"
        connection = mock.MagicMock()
        connection.cursor.side_effect = OperationalError(secret_detail)
        with mock.patch("apps.core.views.connections", {"default": connection}):
            response = client.get(READY)

        assert response.status_code == 503
        assert response.json() == {
            "status": "unavailable",
            "checks": {"database": "unavailable"},
        }
        assert secret_detail not in response.content.decode()
        assert "Readiness check failed" in caplog.text

    def test_returns_503_on_unexpected_query_result(self, client: Client) -> None:
        cursor = mock.MagicMock()
        cursor.__enter__.return_value.fetchone.return_value = None
        connection = mock.MagicMock()
        connection.cursor.return_value = cursor
        with mock.patch("apps.core.views.connections", {"default": connection}):
            response = client.get(READY)

        assert response.status_code == 503

    @pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
    def test_unsafe_methods_rejected(self, client: Client, method: str) -> None:
        assert getattr(client, method)(READY).status_code == 405
