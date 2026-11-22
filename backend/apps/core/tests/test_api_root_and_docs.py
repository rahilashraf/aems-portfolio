"""API root, documentation access, schema content and the public-endpoint allowlist."""

from collections.abc import Callable
from io import StringIO
from typing import Any

import pytest
import yaml
from django.core.management import call_command
from django.test import Client, override_settings

from apps.core.api.permissions import DenyAll
from apps.core.checks import find_public_endpoint_violations
from apps.core.problems import PROBLEM_CONTENT_TYPE

AssertProblem = Callable[..., dict[str, Any]]


class TestApiRoot:
    def test_root_is_public_json(self) -> None:
        response = Client().get("/api/v1/")

        assert response.status_code == 200
        assert response["Content-Type"] == "application/json"
        assert response.json() == {"service": "aems", "api_version": "v1"}
        assert response.has_header("X-Request-ID")

    def test_root_rejects_writes(self, assert_problem: AssertProblem) -> None:
        assert_problem(
            Client().post("/api/v1/", {}, content_type="application/json"),
            405,
            "method_not_allowed",
        )


class TestDocumentationAccess:
    @pytest.mark.parametrize(
        ("path", "content_type"),
        [
            ("/api/schema/", "application/vnd.oai.openapi"),
            ("/api/docs/", "text/html"),
            ("/api/redoc/", "text/html"),
        ],
    )
    def test_enabled_in_development(self, path: str, content_type: str) -> None:
        with override_settings(API_DOCS_ENABLED=True):
            response = Client().get(path)

        assert response.status_code == 200
        assert response["Content-Type"].startswith(content_type)

    @pytest.mark.parametrize("path", ["/api/schema/", "/api/docs/", "/api/redoc/"])
    def test_disabled_returns_problem_404(self, path: str, assert_problem: AssertProblem) -> None:
        with override_settings(API_DOCS_ENABLED=False):
            response = Client().get(path)

        assert_problem(response, 404, "not_found")
        assert b"openapi" not in response.content.lower()


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    out = StringIO()
    call_command("spectacular", "--validate", "--fail-on-warn", stdout=out)
    loaded: dict[str, Any] = yaml.safe_load(out.getvalue())
    return loaded


class TestSchema:
    def test_metadata(self, schema: dict[str, Any]) -> None:
        assert schema["openapi"].startswith("3.")
        assert schema["info"]["title"] == "AEMS API"
        assert schema["info"]["version"] == "v1"

    def test_only_versioned_api_paths(self, schema: dict[str, Any]) -> None:
        assert set(schema["paths"]) == {"/api/v1/"}

    def test_problem_responses_documented(self, schema: dict[str, Any]) -> None:
        responses = schema["paths"]["/api/v1/"]["get"]["responses"]
        assert list(responses) == ["200", "403", "406", "429", "500"]
        for code in ("403", "406", "429", "500"):
            content = responses[code]["content"]
            assert list(content) == [PROBLEM_CONTENT_TYPE]
            assert content[PROBLEM_CONTENT_TYPE]["schema"] == {
                "$ref": "#/components/schemas/ProblemDetails"
            }

    def test_problem_schema_component(self, schema: dict[str, Any]) -> None:
        problem = schema["components"]["schemas"]["ProblemDetails"]
        assert problem["required"] == ["type", "title", "status", "detail", "code", "request_id"]
        assert "errors" in problem["properties"]
        assert "ProblemFieldError" in schema["components"]["schemas"]

    def test_generation_is_deterministic(self) -> None:
        outputs = []
        for _ in range(2):
            out = StringIO()
            call_command("spectacular", stdout=out)
            outputs.append(out.getvalue())
        assert outputs[0] == outputs[1]


def test_problem_hook_adds_body_and_path_parameter_errors() -> None:
    from apps.core.api.openapi import add_problem_responses  # noqa: PLC0415

    result = {
        "paths": {
            "/api/v1/things/{id}/": {
                "parameters": [{"name": "id", "in": "path"}],
                "put": {"requestBody": {}, "responses": {"200": {}}},
            },
            "/api/v1/things/": {
                "get": {"parameters": [{"name": "page", "in": "query"}], "responses": {}}
            },
        }
    }
    out = add_problem_responses(result, None, None, True)

    assert list(out["paths"]["/api/v1/things/{id}/"]["put"]["responses"]) == [
        "200",
        "400",
        "403",
        "404",
        "406",
        "415",
        "429",
        "500",
    ]
    assert list(out["paths"]["/api/v1/things/"]["get"]["responses"]) == [
        "400",
        "403",
        "406",
        "429",
        "500",
    ]


class TestPublicEndpointAllowlist:
    def test_project_urls_have_no_violations(self) -> None:
        assert find_public_endpoint_violations() == []

    def test_manage_check_passes(self) -> None:
        call_command("check", "--fail-level", "ERROR")

    def test_default_permission_is_deny_all(self) -> None:
        from rest_framework.settings import api_settings  # noqa: PLC0415

        permission_classes: Any = api_settings.DEFAULT_PERMISSION_CLASSES
        assert permission_classes == [DenyAll]
        assert api_settings.DEFAULT_AUTHENTICATION_CLASSES == []
        assert api_settings.UNAUTHENTICATED_USER is None


def test_deny_all_denies_object_access() -> None:
    assert DenyAll().has_object_permission(None, None, object()) is False  # type: ignore[arg-type]
    assert DenyAll().has_permission(None, None) is False  # type: ignore[arg-type]
