"""JSON request-body parsing with a structural limit (review finding AEMS-019, ADR-0019).

DRF's ``JSONParser`` reads ``request.body``, so Django's ``DATA_UPLOAD_MAX_MEMORY_SIZE`` caps the
body size; the resulting ``RequestDataTooBig`` is mapped to ``413 request_too_large`` by the
Problem Details handler (:mod:`apps.core.api.exceptions`).

Python's JSON decoder recurses once per nesting level and raises ``RecursionError`` for deep
documents, which DRF does not treat as a parse error (an unhandled 500). :class:`BoundedJSONParser`
maps that to ``400 parse_error`` and also rejects any document nested deeper than
:data:`MAX_JSON_DEPTH` containers, well below the interpreter's recursion limit.
"""

from collections.abc import Mapping
from typing import Any

from rest_framework import exceptions
from rest_framework.parsers import JSONParser

#: Deepest container nesting accepted in a JSON request body. No AEMS endpoint needs more than a
#: few levels; the limit exists to reject pathological documents cheaply.
MAX_JSON_DEPTH = 32


def depth_exceeds(value: Any, limit: int) -> bool:
    """True if ``value`` nests containers deeper than ``limit`` (iterative: cannot overflow)."""
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if isinstance(current, dict):
            children: Any = current.values()
        elif isinstance(current, list):
            children = current
        else:
            continue
        if depth > limit:
            return True
        stack.extend((child, depth + 1) for child in children)
    return False


class BoundedJSONParser(JSONParser):
    """``JSONParser`` that answers deep nesting with a parse error instead of a 500."""

    def parse(
        self,
        stream: Any,
        media_type: str | None = None,
        parser_context: Mapping[str, Any] | None = None,
    ) -> Any:
        try:
            data = super().parse(stream, media_type, parser_context)
        except RecursionError as exc:
            raise exceptions.ParseError() from exc
        if depth_exceeds(data, MAX_JSON_DEPTH):
            raise exceptions.ParseError()
        return data
