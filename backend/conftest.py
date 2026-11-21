"""Shared pytest fixtures."""

import io
import json
import logging
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from django.http import HttpResponse

from apps.core.logging import build_formatter
from apps.core.problems import PROBLEM_CONTENT_TYPE
from apps.core.request_context import clear_request_context


@pytest.fixture(autouse=True)
def _isolate_request_context() -> Iterator[None]:
    clear_request_context()
    yield
    clear_request_context()


class LogCapture:
    """Captures fully rendered log output (the same formatter production uses)."""

    def __init__(self, stream: io.StringIO) -> None:
        self._stream = stream

    @property
    def text(self) -> str:
        return self._stream.getvalue()

    def records(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.text.splitlines() if line.strip()]

    def events(self, name: str) -> list[dict[str, Any]]:
        return [r for r in self.records() if r.get("event") == name]


@pytest.fixture
def json_logs() -> Iterator[LogCapture]:
    """Attach a JSON-rendering handler to the root logger at DEBUG level for one test."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(build_formatter("json"))
    root = logging.getLogger()
    previous_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        yield LogCapture(stream)
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)


@pytest.fixture
def assert_problem() -> Callable[..., dict[str, Any]]:
    """Assert a response is a well-formed RFC 9457 problem and return its body."""

    def _assert(response: HttpResponse, status: int, code: str) -> dict[str, Any]:
        assert response.status_code == status, response.content
        assert response["Content-Type"] == PROBLEM_CONTENT_TYPE
        body: dict[str, Any] = json.loads(response.content)
        assert {"type", "title", "status", "detail", "code", "request_id"} <= body.keys()
        assert body["type"] == "about:blank"
        assert body["status"] == status
        assert body["code"] == code
        assert isinstance(body["detail"], str)
        assert body["detail"]
        assert body["request_id"] == response["X-Request-ID"]
        return body

    return _assert
