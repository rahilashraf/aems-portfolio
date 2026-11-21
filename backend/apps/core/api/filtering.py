"""Filtering and ordering backends with explicit allowlists and stable ordering.

- :class:`AllowlistFilterBackend`: django-filter backend that requires an explicit
  ``filterset_class`` or ``filterset_fields`` list (``"__all__"`` is rejected) and reports invalid
  filter values as ``400 invalid_query_parameters``.
- :class:`StableOrderingFilter`: ``?ordering=`` limited to the view's explicit ``ordering_fields``;
  unknown fields → 400. Every ordering ends with the primary key as a tie-breaker so pagination
  is deterministic. Views must declare a default ``ordering``.
"""

from collections.abc import Mapping
from typing import Any

from django.core.exceptions import ImproperlyConfigured
from django.db.models import Model, QuerySet
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import exceptions
from rest_framework.exceptions import ErrorDetail
from rest_framework.filters import OrderingFilter
from rest_framework.request import Request

from .exceptions import InvalidQueryParameters

ALL_FIELDS = "__all__"
_TIE_BREAKERS = frozenset({"pk", "-pk", "id", "-id"})


class AllowlistFilterBackend(DjangoFilterBackend):  # type: ignore[misc]  # untyped library
    def get_filterset_class(self, view: Any, queryset: QuerySet[Any] | None = None) -> Any:
        if getattr(view, "filterset_fields", None) == ALL_FIELDS:
            msg = f"{type(view).__name__}.filterset_fields must be an explicit list, not '__all__'."
            raise ImproperlyConfigured(msg)
        return super().get_filterset_class(view, queryset)

    def filter_queryset(
        self, request: Request, queryset: QuerySet[Any], view: Any
    ) -> QuerySet[Any]:
        try:
            filtered: QuerySet[Any] = super().filter_queryset(request, queryset, view)
        except exceptions.ValidationError as exc:
            raise InvalidQueryParameters(exc.detail) from exc
        return filtered


class StableOrderingFilter(OrderingFilter):
    def get_valid_fields(
        self, queryset: QuerySet[Any], view: Any, context: Mapping[str, Any] | None = None
    ) -> list[tuple[str, str]]:
        fields = getattr(view, "ordering_fields", None)
        if fields is None or fields == ALL_FIELDS:
            msg = f"{type(view).__name__} must declare an explicit ordering_fields list."
            raise ImproperlyConfigured(msg)
        return [(field, field) for field in fields]

    def get_ordering(self, request: Request, queryset: QuerySet[Any], view: Any) -> list[str]:
        # Validate configuration on every request (fail closed), not only when ?ordering= is sent.
        allowed = {name for name, _ in self.get_valid_fields(queryset, view)}
        default = getattr(view, "ordering", None)
        if not default:
            msg = f"{type(view).__name__} must declare a default ordering."
            raise ImproperlyConfigured(msg)

        raw = request.query_params.get(self.ordering_param)
        if raw is None or not raw.strip():
            ordering = [default] if isinstance(default, str) else list(default)
        else:
            requested = [term.strip() for term in raw.split(",") if term.strip()]
            invalid = [term for term in requested if term.lstrip("-") not in allowed]
            if invalid:
                raise InvalidQueryParameters(
                    {
                        self.ordering_param: [
                            ErrorDetail(f"Unsupported ordering field: {term}", code="invalid")
                            for term in invalid
                        ]
                    }
                )
            ordering = requested
        return self._with_tie_breaker(ordering, queryset.model)

    @staticmethod
    def _with_tie_breaker(ordering: list[str], model: type[Model]) -> list[str]:
        if any(
            term in _TIE_BREAKERS or term.lstrip("-") == model._meta.pk.name for term in ordering
        ):
            return ordering
        return [*ordering, "pk"]
