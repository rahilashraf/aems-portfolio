"""OpenAPI (drf-spectacular) customizations.

:func:`add_problem_responses` is a post-processing hook that documents the standardized RFC 9457
error responses on every operation, so each endpoint's contract shows the error shape clients
must handle. It only adds responses an operation does not already declare and emits them in a
sorted, deterministic order (required for the CI schema drift check).
"""

from http import HTTPStatus
from typing import Any

from apps.core.problems import PROBLEM_CONTENT_TYPE

PROBLEM_SCHEMA_NAME = "ProblemDetails"
PROBLEM_ERROR_SCHEMA_NAME = "ProblemFieldError"
_PROBLEM_REF = {"$ref": f"#/components/schemas/{PROBLEM_SCHEMA_NAME}"}
_HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")

PROBLEM_FIELD_ERROR_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "A single field or query-parameter validation error.",
    "required": ["detail", "code"],
    "properties": {
        "detail": {"type": "string", "description": "Human-readable message."},
        "code": {"type": "string", "description": "Stable machine-readable error code."},
        "pointer": {
            "type": "string",
            "description": "JSON Pointer (URI fragment form) to the invalid request-body member.",
            "example": "#/name",
        },
        "parameter": {
            "type": "string",
            "description": "Name of the invalid query parameter.",
            "example": "page_size",
        },
    },
}

PROBLEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": (
        "RFC 9457 Problem Details. Served as `application/problem+json`. "
        "`code` is the stable identifier clients should branch on."
    ),
    "required": ["type", "title", "status", "detail", "code", "request_id"],
    "properties": {
        "type": {"type": "string", "format": "uri-reference", "example": "about:blank"},
        "title": {"type": "string", "example": "Bad Request"},
        "status": {"type": "integer", "example": 400},
        "detail": {"type": "string", "example": "The request contains invalid data."},
        "code": {"type": "string", "example": "validation_error"},
        "request_id": {
            "type": "string",
            "nullable": True,
            "description": "Correlation ID; also returned in the X-Request-ID header.",
        },
        "errors": {
            "type": "array",
            "items": {"$ref": f"#/components/schemas/{PROBLEM_ERROR_SCHEMA_NAME}"},
        },
    },
}


def _problem_response(status: int) -> dict[str, Any]:
    return {
        "description": HTTPStatus(status).phrase,
        "content": {PROBLEM_CONTENT_TYPE: {"schema": _PROBLEM_REF}},
    }


def _error_statuses(path: str, operation: dict[str, Any]) -> list[int]:
    has_body = "requestBody" in operation
    has_query = any(p.get("in") == "query" for p in operation.get("parameters", []))
    statuses = [403, 406, 429, 500]
    if has_body or has_query:
        statuses.append(400)
    if "{" in path:
        statuses.append(404)
    if has_body:
        statuses.append(415)
    return statuses


def add_problem_responses(
    result: dict[str, Any], generator: Any, request: Any, public: bool
) -> dict[str, Any]:
    schemas = result.setdefault("components", {}).setdefault("schemas", {})
    schemas[PROBLEM_SCHEMA_NAME] = PROBLEM_SCHEMA
    schemas[PROBLEM_ERROR_SCHEMA_NAME] = PROBLEM_FIELD_ERROR_SCHEMA
    result["components"]["schemas"] = dict(sorted(schemas.items()))

    for path, path_item in result.get("paths", {}).items():
        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if operation is None:
                continue
            responses = operation.setdefault("responses", {})
            for status in _error_statuses(path, operation):
                responses.setdefault(str(status), _problem_response(status))
            operation["responses"] = dict(sorted(responses.items()))
    return result
