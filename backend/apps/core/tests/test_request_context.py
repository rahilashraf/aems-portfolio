"""Request IDs, context isolation and access logging."""

import threading
import uuid
from typing import Any

import pytest
from django.http import HttpRequest, HttpResponse
from django.test import Client, RequestFactory

from apps.core.middleware import RequestContextMiddleware
from apps.core.request_context import (
    REQUEST_ID_MAX_LENGTH,
    bind_request_context,
    generate_request_id,
    get_request_id,
    is_valid_request_id,
    resolve_request_id,
)

pytestmark = pytest.mark.urls("tests.fixtures_app.urls")


class TestRequestIdValidation:
    @pytest.mark.parametrize(
        "value",
        [
            "a1b2c3d4",
            "3f0c6f1e-6c1b-4a5e-9a7c-2f3b4d5e6f70",
            "trace.id:abc-123_XYZ",
            "A" * REQUEST_ID_MAX_LENGTH,
        ],
    )
    def test_accepts_safe_ids(self, value: str) -> None:
        assert is_valid_request_id(value)
        assert resolve_request_id(value) == value

    @pytest.mark.parametrize(
        "value",
        [
            None,
            "",
            "short",  # below minimum length
            "A" * (REQUEST_ID_MAX_LENGTH + 1),  # above maximum length
            "has space-12345",
            "newline\ninjected",
            'quote"injected1',
            "<script>alert(1)</script>",
            "-leading-dash-1",
            "unicode-ünïcødé",
        ],
    )
    def test_rejects_unsafe_ids_and_generates_new(self, value: str | None) -> None:
        assert not is_valid_request_id(value)
        generated = resolve_request_id(value)
        assert generated != value
        assert uuid.UUID(generated).version == 4

    def test_generated_ids_are_unique_uuid4(self) -> None:
        ids = {generate_request_id() for _ in range(1000)}
        assert len(ids) == 1000
        assert all(uuid.UUID(i).version == 4 for i in ids)


class TestMiddlewareHttp:
    def test_generates_id_when_absent(self) -> None:
        response = Client().get("/test-api/context/?sleep=0")

        request_id = response["X-Request-ID"]
        assert uuid.UUID(request_id).version == 4
        body = response.json()
        assert body == {"before": request_id, "after": request_id, "attribute": request_id}

    def test_propagates_valid_supplied_id(self) -> None:
        response = Client().get("/test-api/context/?sleep=0", HTTP_X_REQUEST_ID="client-trace-0001")

        assert response["X-Request-ID"] == "client-trace-0001"
        assert response.json()["after"] == "client-trace-0001"

    def test_replaces_invalid_supplied_id(self) -> None:
        response = Client().get(
            "/test-api/context/?sleep=0", HTTP_X_REQUEST_ID="bad id\r\nX-Evil: 1"
        )

        assert response["X-Request-ID"] != "bad id\r\nX-Evil: 1"
        assert uuid.UUID(response["X-Request-ID"]).version == 4
        assert "X-Evil" not in response

    def test_every_response_carries_an_id(self) -> None:
        client = Client(raise_request_exception=False)
        for path in ("/health/live/", "/no-such-page/", "/test-django/crash/", "/api/v1/"):
            assert client.get(path).has_header("X-Request-ID"), path

    def test_context_is_cleared_after_success_and_error(self) -> None:
        client = Client(raise_request_exception=False)
        client.get("/test-api/context/?sleep=0")
        assert get_request_id() is None
        client.get("/test-api/unhandled/")
        assert get_request_id() is None
        client.get("/test-django/crash/")
        assert get_request_id() is None


class TestMiddlewareUnit:
    def test_clears_stale_context_before_request(self) -> None:
        bind_request_context(request_id="stale-request-id", user_id="leaked")
        seen: dict[str, Any] = {}

        def view(request: HttpRequest) -> HttpResponse:
            import structlog  # noqa: PLC0415

            seen.update(structlog.contextvars.get_contextvars())
            return HttpResponse()

        RequestContextMiddleware(view)(RequestFactory().get("/"))

        assert "user_id" not in seen
        assert seen["request_id"] != "stale-request-id"

    def test_clears_context_when_downstream_raises(self) -> None:
        def exploding(request: HttpRequest) -> HttpResponse:
            assert get_request_id() is not None
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            RequestContextMiddleware(exploding)(RequestFactory().get("/"))

        assert get_request_id() is None


class TestConcurrentIsolation:
    def test_concurrent_requests_never_share_ids(self, json_logs: Any) -> None:
        count = 16
        barrier = threading.Barrier(count)
        results: dict[str, Any] = {}
        errors: list[BaseException] = []

        def worker(index: int) -> None:
            supplied = f"thread-req-{index:04d}"
            try:
                barrier.wait(timeout=10)
                response = Client().get(
                    f"/test-api/context/?sleep=0.05&marker={supplied}", HTTP_X_REQUEST_ID=supplied
                )
                results[supplied] = (response["X-Request-ID"], response.json())
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        assert not errors
        assert len(results) == count
        for supplied, (header, body) in results.items():
            assert header == supplied
            assert body == {"before": supplied, "after": supplied, "attribute": supplied}

        # Every log line emitted inside a request carries that request's own ID.
        context_events = json_logs.events("fixture.context")
        assert len(context_events) == count
        assert all(e["request_id"] == e["marker"] for e in context_events)
        completed = [
            e for e in json_logs.events("request.completed") if e["route"] == "test-api/context/"
        ]
        assert sorted(e["request_id"] for e in completed) == sorted(results)


class TestAccessLog:
    def test_completed_request_is_logged_without_path_or_query(self, json_logs: Any) -> None:
        Client().get(
            "/test-api/context/?sleep=0&token=tok_secret_value&password=hunter2",
            HTTP_X_REQUEST_ID="access-log-0001",
            HTTP_AUTHORIZATION="Basic tok_header_secret",
            HTTP_COOKIE="sessionid=cookie_secret_value",
            HTTP_X_FORWARDED_FOR="203.0.113.99",
        )

        [event] = [
            e for e in json_logs.events("request.completed") if e["request_id"] == "access-log-0001"
        ]
        assert event["method"] == "GET"
        assert event["route"] == "test-api/context/"
        assert event["status_code"] == 200
        assert event["level"] == "info"
        assert isinstance(event["duration_ms"], float)
        assert event["client_ip"] == "127.0.0.1"  # REMOTE_ADDR; X-Forwarded-For is not trusted
        for secret in (
            "tok_secret_value",
            "hunter2",
            "tok_header_secret",
            "cookie_secret_value",
            "203.0.113.99",
        ):
            assert secret not in json_logs.text

    def test_unresolved_route_is_logged_as_null(self, json_logs: Any) -> None:
        Client().get("/invitations/raw-token-in-path-123/", HTTP_X_REQUEST_ID="access-log-0002")

        [event] = [
            e for e in json_logs.events("request.completed") if e["request_id"] == "access-log-0002"
        ]
        assert event["route"] is None
        assert event["status_code"] == 404
        assert "raw-token-in-path-123" not in json_logs.text

    def test_health_probes_log_at_debug(self, json_logs: Any) -> None:
        Client().get("/health/live/", HTTP_X_REQUEST_ID="access-log-0003")

        [event] = [
            e for e in json_logs.events("request.completed") if e["request_id"] == "access-log-0003"
        ]
        assert event["level"] == "debug"


class TestDjangoRequestLogCorrelation:
    def test_django_request_warnings_carry_the_request_id(self, json_logs: Any) -> None:
        Client().get("/no-such-page-for-correlation/", HTTP_X_REQUEST_ID="django-log-corr-01")

        [record] = [r for r in json_logs.records() if r["logger"] == "django.request"]
        assert record["event"] == "Not Found: [path redacted]"
        assert record["request_id"] == "django-log-corr-01"
        assert get_request_id() is None  # cleared once the response was closed

    def test_request_finished_receiver_clears_context(self) -> None:
        from apps.core.request_context import (  # noqa: PLC0415
            clear_request_context_on_request_finished,
        )

        bind_request_context(request_id="pending-request-01")
        clear_request_context_on_request_finished(sender=None)
        assert get_request_id() is None
