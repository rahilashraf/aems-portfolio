"""AEMS-008 / AEMS-009: bounded redaction and exception-detail safety (responses and logs)."""

import json
from collections.abc import Callable
from typing import Any

import pytest
from django.test import Client

from apps.core.api.exceptions import (
    MAX_MESSAGE_LENGTH,
    MAX_REPORTED_ERRORS,
    SENSITIVE_FIELD_MESSAGE,
    flatten_validation_errors,
)
from apps.core.sanitization import (
    CIRCULAR,
    MAX_DEPTH,
    MAX_ITEMS,
    MAX_NODES,
    MAX_TEXT_LENGTH,
    REDACTED,
    TRUNCATED,
    redact_structure,
    sanitize_text,
)
from tests.fixtures_app.views import SENSITIVE_VALUES

AssertProblem = Callable[..., dict[str, Any]]


def _assert_clean(text: str) -> None:
    for name, value in SENSITIVE_VALUES.items():
        assert value not in text, f"{name} leaked"


# --------------------------------------------------------------------------- AEMS-008
class TestBoundedRedaction:
    def test_deeply_nested_dict_is_truncated_not_returned_raw(self) -> None:
        value: dict[str, Any] = {"leaf": "visible", "token": "t"}
        for _ in range(MAX_DEPTH + 5):
            value = {"level": value}
        result = redact_structure(value)

        node = result
        for _ in range(MAX_DEPTH - 1):
            node = node["level"]
        assert node["level"] == TRUNCATED

    def test_secret_beyond_depth_limit_never_survives(self) -> None:
        value: Any = {"password": "deep-secret-123"}
        for _ in range(MAX_DEPTH * 3):
            value = [value]
        assert "deep-secret-123" not in json.dumps(redact_structure(value))

    def test_mixed_nested_structures(self) -> None:
        value = {
            "items": [{"token": "a"}, ("tuple", {"password": "b"}), {"set": {"x"}}],
            "headers": {"Authorization": "Bearer secretvalue1", "Accept": "json"},
        }
        result = redact_structure(value)
        assert result["items"][0] == {"token": REDACTED}
        assert result["items"][1] == ("tuple", {"password": REDACTED})
        assert result["items"][2] == {"set": ["x"]}
        assert result["headers"] == {"Authorization": REDACTED, "Accept": "json"}

    def test_circular_references_terminate(self) -> None:
        cyclic: dict[str, Any] = {"name": "root"}
        cyclic["self"] = cyclic
        looped: list[Any] = []
        looped.append(looped)
        assert redact_structure(cyclic) == {"name": "root", "self": CIRCULAR}
        assert redact_structure(looped) == [CIRCULAR]

    def test_shared_non_circular_references_are_not_marked_circular(self) -> None:
        shared = {"a": 1}
        assert redact_structure({"x": shared, "y": shared}) == {"x": {"a": 1}, "y": {"a": 1}}

    def test_large_containers_are_capped(self) -> None:
        result = redact_structure({"items": list(range(MAX_ITEMS * 5))})
        assert len(result["items"]) == MAX_ITEMS + 1
        assert result["items"][-1] == f"{TRUNCATED} {MAX_ITEMS * 4} more items"

        wide = redact_structure({f"k{i}": i for i in range(MAX_ITEMS + 7)})
        assert wide[TRUNCATED] == "7 more entries"

    def test_total_node_budget_bounds_work(self) -> None:
        wide_and_deep = [[list(range(MAX_ITEMS)) for _ in range(MAX_ITEMS)] for _ in range(5)]
        rendered = json.dumps(redact_structure(wide_and_deep))
        assert rendered.count(TRUNCATED) > 0
        assert sum(1 for _ in rendered.split(",")) <= MAX_NODES + MAX_ITEMS * 5

    def test_strings_inside_structures_are_sanitized(self) -> None:
        result = redact_structure({"message": "connect postgres://u:pw-secret@h/db"})
        assert result["message"] == f"connect postgres://u:{REDACTED}@h/db"


class TestSanitizeText:
    @pytest.mark.parametrize(
        ("text", "secret"),
        [
            ("postgresql://aems:p4ss-word@db:5432/aems", "p4ss-word"),
            ("redis://:only-pass@cache:6379/0", "only-pass"),
            ("password=hunter2 user=bob", "hunter2"),
            ('{"password": "hunter2"}', "hunter2"),
            ("client_secret: abcd1234", "abcd1234"),
            ("Authorization: Bearer abcdef0123456789", "abcdef0123456789"),
            ("Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="),
            ("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", "c2lnbmF0dXJl"),
            ("GET https://x.example/cb?code=abc123&state=zz", "abc123"),
            ("DETAIL:  Key (email)=(a@b.example) already exists.", "a@b.example"),
            ("LINE 1: SELECT 1 WHERE pw = 'quoted-secret'", "quoted-secret"),
            ("api_key=AKIA0000EXAMPLE sessionid=s3ss csrftoken=c5rf", "AKIA0000EXAMPLE"),
        ],
    )
    def test_secrets_are_removed(self, text: str, secret: str) -> None:
        cleaned = sanitize_text(text)
        assert secret not in cleaned
        assert REDACTED in cleaned

    def test_harmless_text_is_unchanged(self) -> None:
        text = "Organization not found for slug demo-school (status 404)."
        assert sanitize_text(text) == text

    def test_long_text_is_capped(self) -> None:
        cleaned = sanitize_text("x" * (MAX_TEXT_LENGTH * 3))
        assert len(cleaned) < MAX_TEXT_LENGTH + 32
        assert cleaned.endswith(TRUNCATED)


# --------------------------------------------------------------------------- AEMS-009
@pytest.mark.urls("tests.fixtures_app.urls")
class TestExceptionDetailSafety:
    URL = "/test-api/sensitive-errors/"

    def test_unexpected_exception_response_and_log_are_clean(
        self, assert_problem: AssertProblem, json_logs: Any
    ) -> None:
        response = Client(raise_request_exception=False).get(self.URL)

        body = assert_problem(response, 500, "internal_error")
        assert body["detail"] == "An unexpected error occurred."
        _assert_clean(response.content.decode())

        [event] = json_logs.events("request.unhandled_exception")
        assert "RuntimeError" in event["exception"]
        assert "Traceback" in event["exception"]
        assert REDACTED in event["exception"]
        _assert_clean(json_logs.text)

    def test_tracebacks_do_not_render_local_variables(self, json_logs: Any) -> None:
        # Source lines may name variables; their runtime values must never be rendered.
        Client(raise_request_exception=False).get(self.URL)
        assert SENSITIVE_VALUES["local"] not in json_logs.text

    def test_domain_error_message_is_sanitized_safety_net(
        self, assert_problem: AssertProblem
    ) -> None:
        response = Client().get(self.URL, {"kind": "domain"})

        body = assert_problem(response, 409, "conflict")
        assert body["detail"].startswith("Duplicate entry;")
        assert len(body["detail"]) <= MAX_MESSAGE_LENGTH
        _assert_clean(response.content.decode())

    def test_non_domain_api_exception_detail_is_replaced(
        self, assert_problem: AssertProblem
    ) -> None:
        response = Client().get(self.URL, {"kind": "non-domain"})

        body = assert_problem(response, 418, "teapot")
        assert body["detail"] == "The request could not be completed."
        _assert_clean(response.content.decode())

    def test_permission_denied_message_is_generic(self, assert_problem: AssertProblem) -> None:
        response = Client().get(self.URL, {"kind": "permission"})

        body = assert_problem(response, 403, "permission_denied")
        assert body["detail"] == "You do not have permission to perform this action."
        _assert_clean(response.content.decode())

    def test_django_validation_error_message_is_sanitized(
        self, assert_problem: AssertProblem
    ) -> None:
        response = Client().get(self.URL, {"kind": "django-validation"})

        body = assert_problem(response, 400, "validation_error")
        assert body["errors"][0]["pointer"] == "#/email"
        _assert_clean(response.content.decode())

    def test_parse_error_does_not_echo_body_or_parser_internals(
        self, assert_problem: AssertProblem
    ) -> None:
        raw = '{"password": "' + SENSITIVE_VALUES["db_password"] + '", oops'
        response = Client().post("/test-api/echo/", raw, content_type="application/json")

        body = assert_problem(response, 400, "parse_error")
        assert body["detail"] == "The request body could not be parsed."
        assert "Expecting" not in body["detail"]  # json.JSONDecodeError text
        _assert_clean(response.content.decode())


@pytest.mark.urls("tests.fixtures_app.urls")
class TestValidationMessageSafety:
    URL = "/test-api/sensitive-validation/"

    def _post(self, payload: dict[str, Any]) -> Any:
        return Client().post(self.URL, payload, content_type="application/json")

    def test_sensitive_fields_get_generic_messages(self, assert_problem: AssertProblem) -> None:
        response = self._post(
            {"username": "alice", "password": "pw-echo-1", "api_token": "tok-echo-2"}
        )

        body = assert_problem(response, 400, "validation_error")
        by_pointer = {e["pointer"]: e for e in body["errors"]}
        assert by_pointer["#/password"]["detail"] == SENSITIVE_FIELD_MESSAGE
        assert by_pointer["#/api_token"]["detail"] == SENSITIVE_FIELD_MESSAGE
        text = response.content.decode()
        for echoed in ("pw-echo-1", "tok-echo-2"):
            assert echoed not in text

    def test_non_sensitive_field_messages_are_sanitized(
        self, assert_problem: AssertProblem
    ) -> None:
        response = self._post({"username": "alice", "password": "x"})

        body = assert_problem(response, 400, "validation_error")
        [username_error] = [e for e in body["errors"] if e["pointer"] == "#/username"]
        assert username_error["detail"].startswith("User alice rejected;")
        _assert_clean(response.content.decode())

    def test_number_of_reported_errors_is_capped(self, assert_problem: AssertProblem) -> None:
        response = self._post(
            {"username": "a", "password": "b", "notes": ["x"] * (MAX_REPORTED_ERRORS * 2)}
        )

        body = assert_problem(response, 400, "validation_error")
        assert len(body["errors"]) == MAX_REPORTED_ERRORS


class TestValidationFlattening:
    def test_messages_are_length_capped(self) -> None:
        [error] = flatten_validation_errors({"name": ["y" * 5000]}, query_parameters=False)
        assert len(error["detail"]) == MAX_MESSAGE_LENGTH
        assert error["detail"].endswith("...")

    @pytest.mark.parametrize("code", ["Bad Code", "x" * 80, "drop table;", ""])
    def test_unsafe_error_codes_are_normalized(self, code: str) -> None:
        from rest_framework.exceptions import ErrorDetail  # noqa: PLC0415

        [error] = flatten_validation_errors(
            {"name": [ErrorDetail("bad", code=code)]}, query_parameters=False
        )
        assert error["code"] == "invalid"

    def test_nested_sensitive_path_segment_is_generic(self) -> None:
        [error] = flatten_validation_errors(
            {"credentials": {"secret": ["Secret s3 is wrong"]}}, query_parameters=False
        )
        assert error["detail"] == SENSITIVE_FIELD_MESSAGE
        assert error["pointer"] == "#/credentials/secret"
