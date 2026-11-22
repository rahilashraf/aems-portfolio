"""End-to-end Problem Details behaviour: status, headers, content type and body structure."""

import json
from collections.abc import Callable
from typing import Any

import pytest
from django.test import Client

from tests.fixtures_app.views import SECRET_INTERNAL_MESSAGE

pytestmark = pytest.mark.urls("tests.fixtures_app.urls")

AssertProblem = Callable[..., dict[str, Any]]
SENSITIVE_FRAGMENTS = (
    "password",
    "Traceback",
    "SELECT",
    "/srv/app",
    "tok_live",
    "psycopg",
    "SecretModel",
    "tenant=42",
    "R-17",
    "abc123",
    "ACL",
)


def _assert_no_leak(response: Any) -> None:
    body = response.content.decode()
    for fragment in SENSITIVE_FRAGMENTS:
        assert fragment not in body, fragment


@pytest.fixture
def client() -> Client:
    return Client(raise_request_exception=False)


class TestValidationErrors:
    def test_field_errors_use_json_pointers(self, client: Client, assert_problem: AssertProblem):
        payload = {
            "name": "x" * 11,
            "quantity": 0,
            "items": [{"sku": "ok"}, {"sku": "toolong"}],
            "tags": ["abcd"],
        }
        response = client.post("/test-api/echo/", payload, content_type="application/json")

        body = assert_problem(response, 400, "validation_error")
        assert body["title"] == "Bad Request"
        assert body["detail"] == "The request contains invalid data."
        pointers = {(e["pointer"], e["code"]) for e in body["errors"]}
        assert pointers == {
            ("#/name", "max_length"),
            ("#/quantity", "min_value"),
            ("#/items/1/sku", "max_length"),
            ("#/tags/0", "max_length"),
        }
        assert all(e["detail"] for e in body["errors"])

    def test_missing_fields_report_required(self, client: Client, assert_problem: AssertProblem):
        response = client.post("/test-api/echo/", {}, content_type="application/json")

        body = assert_problem(response, 400, "validation_error")
        assert {(e["pointer"], e["code"]) for e in body["errors"]} == {
            ("#/name", "required"),
            ("#/quantity", "required"),
        }

    def test_non_field_errors_point_at_document_root(
        self, client: Client, assert_problem: AssertProblem
    ):
        response = client.post(
            "/test-api/echo/", {"name": "forbidden", "quantity": 1}, content_type="application/json"
        )

        body = assert_problem(response, 400, "validation_error")
        assert body["errors"] == [
            {"detail": "This combination is not allowed.", "code": "invalid", "pointer": "#"}
        ]

    def test_pointer_tokens_are_escaped(self) -> None:
        from apps.core.api.exceptions import flatten_validation_errors  # noqa: PLC0415

        errors = flatten_validation_errors({"a/b~c": ["bad"]}, query_parameters=False)
        assert errors[0]["pointer"] == "#/a~1b~0c"

    def test_scalar_detail_is_supported(self) -> None:
        from apps.core.api.exceptions import flatten_validation_errors  # noqa: PLC0415

        assert flatten_validation_errors("bad", query_parameters=True) == [
            {"detail": "bad", "code": "invalid", "parameter": ""}
        ]

    def test_django_validation_error_is_translated(
        self, client: Client, assert_problem: AssertProblem
    ):
        body = assert_problem(client.get("/test-api/django-validation/"), 400, "validation_error")
        assert body["errors"][0]["pointer"] == "#/email"

    def test_malformed_json_is_a_parse_error(self, client: Client, assert_problem: AssertProblem):
        response = client.post("/test-api/echo/", "{not json", content_type="application/json")

        assert_problem(response, 400, "parse_error")


class TestAuthenticationAndAuthorization:
    def test_default_permission_denies(self, client: Client, assert_problem: AssertProblem):
        body = assert_problem(client.get("/test-api/implicit/"), 403, "permission_denied")
        assert body["title"] == "Forbidden"

    def test_not_authenticated_keeps_www_authenticate(
        self, client: Client, assert_problem: AssertProblem
    ):
        response = client.get("/test-api/auth-required/")

        assert_problem(response, 401, "not_authenticated")
        assert response["WWW-Authenticate"] == 'Bearer realm="api"'

    def test_authentication_failed_keeps_www_authenticate(
        self, client: Client, assert_problem: AssertProblem
    ):
        response = client.get("/test-api/auth-failed/")

        body = assert_problem(response, 401, "authentication_failed")
        # The view raised AuthenticationFailed("Invalid token."): only the generic text is sent.
        assert body["detail"] == "Authentication credentials were invalid."
        assert response["WWW-Authenticate"] == 'Bearer realm="api"'

    def test_django_permission_denied_is_generic(
        self, client: Client, assert_problem: AssertProblem
    ):
        response = client.get("/test-api/django-403/")

        body = assert_problem(response, 403, "permission_denied")
        assert body["detail"] == "You do not have permission to perform this action."
        _assert_no_leak(response)


class TestHttpProtocolErrors:
    def test_not_found_from_django_404_is_generic(
        self, client: Client, assert_problem: AssertProblem
    ):
        response = client.get("/test-api/django-404/")

        body = assert_problem(response, 404, "not_found")
        assert body["detail"] == "The requested resource was not found."
        _assert_no_leak(response)

    def test_method_not_allowed_keeps_allow_header(
        self, client: Client, assert_problem: AssertProblem
    ):
        response = client.delete("/test-api/echo/")

        assert_problem(response, 405, "method_not_allowed")
        assert set(response["Allow"].replace(" ", "").split(",")) >= {"GET", "POST"}

    def test_unsupported_media_type(self, client: Client, assert_problem: AssertProblem):
        response = client.post("/test-api/echo/", {"name": "a"})  # multipart form data

        assert_problem(response, 415, "unsupported_media_type")

    def test_not_acceptable(self, client: Client, assert_problem: AssertProblem):
        response = client.get("/test-api/echo/", HTTP_ACCEPT="application/xml")

        assert_problem(response, 406, "not_acceptable")

    def test_problem_json_accept_header_is_honoured_alongside_json(self, client: Client):
        response = client.get(
            "/test-api/echo/", HTTP_ACCEPT="application/json, application/problem+json"
        )
        assert response.status_code == 200

    def test_throttled_keeps_retry_after(self, client: Client, assert_problem: AssertProblem):
        response = client.get("/test-api/throttled/")

        assert_problem(response, 429, "throttled")
        assert response["Retry-After"] == "42"

    def test_conflict(self, client: Client, assert_problem: AssertProblem):
        body = assert_problem(client.post("/test-api/conflict/"), 409, "conflict")
        assert body["title"] == "Conflict"

    def test_generic_api_exception_gets_stable_code(
        self, client: Client, assert_problem: AssertProblem
    ):
        assert_problem(client.get("/test-api/api-exception/"), 500, "api_error")


class TestUnexpectedErrors:
    def test_drf_unhandled_exception_is_generic_500(
        self, client: Client, assert_problem: AssertProblem, json_logs: Any
    ):
        response = client.get("/test-api/unhandled/", HTTP_X_REQUEST_ID="trace-unhandled-01")

        body = assert_problem(response, 500, "internal_error")
        assert body["detail"] == "An unexpected error occurred."
        assert body["request_id"] == "trace-unhandled-01"
        _assert_no_leak(response)
        [event] = json_logs.events("request.unhandled_exception")
        assert event["request_id"] == "trace-unhandled-01"
        assert event["level"] == "error"
        assert "RuntimeError" in event["exception"]

    def test_django_view_crash_uses_handler500(self, client: Client, assert_problem: AssertProblem):
        response = client.get("/test-django/crash/")

        assert_problem(response, 500, "internal_error")
        _assert_no_leak(response)
        assert SECRET_INTERNAL_MESSAGE not in response.content.decode()


class TestDjangoLevelErrors:
    def test_unknown_url(self, client: Client, assert_problem: AssertProblem):
        body = assert_problem(client.get("/no/such/path/"), 404, "not_found")
        assert body["detail"] == "The requested resource was not found."

    def test_unknown_api_url(self, client: Client, assert_problem: AssertProblem):
        assert_problem(client.get("/api/v1/does-not-exist/"), 404, "not_found")

    def test_suspicious_operation(self, client: Client, assert_problem: AssertProblem):
        response = client.get("/test-django/suspicious/")

        assert_problem(response, 400, "bad_request")
        _assert_no_leak(response)

    def test_disallowed_host(self, client: Client, assert_problem: AssertProblem):
        response = client.get("/api/v1/", HTTP_HOST="evil.example")

        assert_problem(response, 400, "bad_request")

    def test_django_permission_denied(self, client: Client, assert_problem: AssertProblem):
        response = client.get("/test-django/forbidden/")

        assert_problem(response, 403, "permission_denied")
        _assert_no_leak(response)

    def test_csrf_failure(self, assert_problem: AssertProblem):
        client = Client(enforce_csrf_checks=True)
        response = client.post("/test-django/csrf/", {})

        body = assert_problem(response, 403, "csrf_failed")
        assert body["detail"] == "CSRF verification failed."


def test_success_responses_are_plain_json(client: Client) -> None:
    response = client.post(
        "/test-api/echo/", {"name": "ok", "quantity": 2}, content_type="application/json"
    )
    assert response.status_code == 201
    assert response["Content-Type"] == "application/json"
    assert json.loads(response.content) == {"name": "ok", "quantity": 2}
