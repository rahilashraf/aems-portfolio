"""Standard page-number pagination.

- ``?page=`` (default 1) and ``?page_size=`` (default 25, maximum 100).
- Non-integer or non-positive ``page``/``page_size`` → 400 ``invalid_query_parameters``.
- ``page_size`` above the maximum is capped at 100; the effective size is reported in the body.
- A page beyond the last page → 404 ``page_not_found``.
- Response shape: ``count``, ``page``, ``page_size``, ``total_pages``, ``next``, ``previous``,
  ``results`` (always present, in this order).
"""

from collections.abc import Sequence
from typing import Any

from django.db.models import QuerySet
from rest_framework import exceptions
from rest_framework.exceptions import ErrorDetail
from rest_framework.pagination import PageNumberPagination
from rest_framework.request import Request
from rest_framework.response import Response

from .exceptions import InvalidQueryParameters

DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100


class PageNotFound(exceptions.NotFound):
    default_detail = "The requested page does not exist."
    default_code = "page_not_found"


def _positive_int_or_none(raw: str | None) -> int | None:
    """Parse a strictly positive integer; None if absent; raise ValueError if invalid."""
    if raw is None:
        return None
    if not (raw.isascii() and raw.isdigit()):  # rejects signs, spaces, decimals, non-ASCII digits
        raise ValueError(raw)
    value = int(raw)
    if value < 1:
        raise ValueError(raw)
    return value


class StandardPagination(PageNumberPagination):
    page_size = DEFAULT_PAGE_SIZE
    page_size_query_param = "page_size"
    max_page_size = MAX_PAGE_SIZE
    page_query_param = "page"
    last_page_strings = ()

    def _validate_query_parameters(self, request: Request) -> None:
        errors: dict[str, list[ErrorDetail]] = {}
        for name in (self.page_query_param, self.page_size_query_param):
            try:
                _positive_int_or_none(request.query_params.get(name))
            except ValueError:
                errors[name] = [ErrorDetail("Must be a positive integer.", code="invalid")]
        if errors:
            raise InvalidQueryParameters(errors)

    def get_page_size(self, request: Request) -> int:
        requested = _positive_int_or_none(request.query_params.get(self.page_size_query_param))
        if requested is None:
            return self.page_size
        return min(requested, self.max_page_size)

    def paginate_queryset(
        self, queryset: QuerySet[Any] | Sequence[Any], request: Request, view: Any = None
    ) -> list[Any] | None:
        self._validate_query_parameters(request)
        try:
            return super().paginate_queryset(queryset, request, view)  # type: ignore[arg-type]
        except exceptions.NotFound as exc:
            raise PageNotFound() from exc

    def get_paginated_response(self, data: Any) -> Response:
        page = self.page
        if page is None:  # pragma: no cover - only reachable if called before paginate_queryset
            msg = "get_paginated_response() called before paginate_queryset()."
            raise RuntimeError(msg)
        return Response(
            {
                "count": page.paginator.count,
                "page": page.number,
                "page_size": page.paginator.per_page,
                "total_pages": page.paginator.num_pages,
                "next": self.get_next_link(),
                "previous": self.get_previous_link(),
                "results": data,
            }
        )

    def get_paginated_response_schema(self, schema: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "object",
            "required": [
                "count",
                "page",
                "page_size",
                "total_pages",
                "next",
                "previous",
                "results",
            ],
            "properties": {
                "count": {"type": "integer", "example": 120},
                "page": {"type": "integer", "example": 2},
                "page_size": {"type": "integer", "example": DEFAULT_PAGE_SIZE},
                "total_pages": {"type": "integer", "example": 5},
                "next": {"type": "string", "format": "uri", "nullable": True},
                "previous": {"type": "string", "format": "uri", "nullable": True},
                "results": schema,
            },
        }
