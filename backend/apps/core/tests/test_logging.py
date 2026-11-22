"""Structured logging configuration and sensitive-data redaction."""

import io
import json
import logging
from typing import Any

import pytest
import structlog
from django.test import Client

from apps.core.logging import (
    build_formatter,
    build_logging_config,
    redact_sensitive_values,
)
from apps.core.sanitization import REDACTED


class TestRedactionProcessor:
    @pytest.mark.parametrize(
        "key",
        [
            "password",
            "new_password",
            "passwd",
            "secret",
            "client_secret",
            "token",
            "refresh_token",
            "access_token",
            "Authorization",
            "cookie",
            "set-cookie",
            "sessionid",
            "csrftoken",
            "api_key",
            "api-key",
            "credentials",
            "signature",
            "private_key",
        ],
    )
    def test_redacts_sensitive_top_level_keys(self, key: str) -> None:
        event = redact_sensitive_values(None, "info", {"event": "x", key: "value"})
        assert event[key] == REDACTED

    def test_redacts_nested_structures(self) -> None:
        event = redact_sensitive_values(
            None,
            "info",
            {
                "event": "x",
                "headers": {"Authorization": "Bearer abc", "Accept": "json"},
                "items": [{"token": "t1", "id": 1}, ("tuple", {"password": "p"})],
            },
        )
        assert event["headers"] == {"Authorization": REDACTED, "Accept": "json"}
        assert event["items"][0] == {"token": REDACTED, "id": 1}
        assert event["items"][1][1] == {"password": REDACTED}

    def test_keeps_non_sensitive_values_and_event_name(self) -> None:
        event = redact_sensitive_values(
            None, "info", {"event": "token.rotated", "status_code": 200, "route": "a/"}
        )
        assert event == {"event": "token.rotated", "status_code": 200, "route": "a/"}

    def test_depth_limit_stops_recursion(self) -> None:
        deep: dict[str, Any] = {"password": "p"}
        for _ in range(12):
            deep = {"level": deep}
        event = redact_sensitive_values(None, "info", {"event": "x", "data": deep})
        assert event["data"]  # processed without error


class TestFormatters:
    def _render(self, log_format: str) -> str:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(build_formatter(log_format))  # type: ignore[arg-type]
        logger = logging.getLogger("tests.formatter")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        try:
            structlog.contextvars.bind_contextvars(request_id="fmt-req-0001")
            logger.info("stdlib message %s", "arg", extra={"password": "should-not-appear"})
            structlog.get_logger("tests.formatter").info("structured.event", token="t0k3n", count=3)
            try:
                raise ValueError("boom")
            except ValueError:
                structlog.get_logger("tests.formatter").exception("failure.event")
        finally:
            logger.removeHandler(handler)
            logger.propagate = True
        return stream.getvalue()

    def test_json_output_is_one_object_per_line_with_context(self) -> None:
        lines = [json.loads(line) for line in self._render("json").splitlines()]

        assert [line["event"] for line in lines] == [
            "stdlib message arg",
            "structured.event",
            "failure.event",
        ]
        for line in lines:
            assert line["request_id"] == "fmt-req-0001"
            assert line["logger"] == "tests.formatter"
            assert line["timestamp"].endswith("Z")
        assert lines[1]["token"] == REDACTED
        assert lines[1]["count"] == 3
        assert "ValueError: boom" in lines[2]["exception"]

    def test_stdlib_extra_attributes_are_not_rendered(self) -> None:
        assert "should-not-appear" not in self._render("json")

    def test_console_output_is_human_readable(self) -> None:
        output = self._render("console")
        assert "structured.event" in output
        assert "fmt-req-0001" in output
        assert "t0k3n" not in output
        assert not output.lstrip().startswith("{")


class TestLoggingConfig:
    def test_sql_logging_is_suppressed(self) -> None:
        config = build_logging_config(level="DEBUG", log_format="json")
        assert config["loggers"]["django.db.backends"]["level"] == "WARNING"

    def test_rejects_unknown_format(self) -> None:
        with pytest.raises(ValueError, match="Unsupported log format"):
            build_logging_config(level="INFO", log_format="xml")  # type: ignore[arg-type]


@pytest.mark.urls("tests.fixtures_app.urls")
def test_request_logging_redacts_sensitive_data_end_to_end(json_logs: Any) -> None:
    Client().post(
        "/test-api/sensitive-logging/?api_key=query_secret_1",
        {"password": "body_secret_pw"},
        content_type="application/json",
        HTTP_AUTHORIZATION="Bearer header_secret_tok",
        HTTP_X_REQUEST_ID="sensitive-req-01",
    )

    [event] = json_logs.events("fixture.sensitive")
    assert event["request_id"] == "sensitive-req-01"
    assert event["password"] == REDACTED
    assert event["token"] == REDACTED
    assert event["headers"] == {"Authorization": REDACTED, "Accept": "json"}
    assert event["nested"] == {"api_key": REDACTED, "safe": "visible-value"}
    for secret in (
        "body_secret_pw",
        "header_secret_tok",
        "tok_live_123",
        "key_abc",
        "query_secret_1",
    ):
        assert secret not in json_logs.text


class TestDjangoRequestPathRedaction:
    @pytest.mark.urls("tests.fixtures_app.urls")
    def test_django_request_warnings_do_not_contain_paths(self, json_logs: Any) -> None:
        client = Client(raise_request_exception=False)
        client.get("/invitations/one-time-token-abc123/")
        client.get("/test-django/crash/?reset_token=qs-secret-999")

        records = [r for r in json_logs.records() if r["logger"] == "django.request"]
        assert {r["event"] for r in records} == {
            "Not Found: [path redacted]",
            "Internal Server Error: [path redacted]",
        }
        assert "one-time-token-abc123" not in json_logs.text
        assert "qs-secret-999" not in json_logs.text
        assert "/test-django/crash/" not in json_logs.text

    def test_dev_server_request_line_is_reduced_to_method(self) -> None:
        from apps.core.logging import RedactRequestPathFilter  # noqa: PLC0415

        record = logging.LogRecord(
            "django.server",
            logging.INFO,
            __file__,
            1,
            '"%s" %s %s',
            ("GET /reset/?token=abc HTTP/1.1", "200", "12"),
            None,
        )
        assert RedactRequestPathFilter().filter(record)
        assert record.getMessage() == '"GET [path redacted]" 200 12'

    def test_records_without_args_are_untouched(self) -> None:
        from apps.core.logging import RedactRequestPathFilter  # noqa: PLC0415

        record = logging.LogRecord(
            "django.request", logging.WARNING, __file__, 1, "plain", None, None
        )
        assert RedactRequestPathFilter().filter(record)
        assert record.getMessage() == "plain"
