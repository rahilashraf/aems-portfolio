import django_filters

from ..models import AuditLog, AuditOutcome


class AuditLogFilterSet(django_filters.FilterSet):  # type: ignore[misc]  # untyped library
    """Allowlisted audit filters. Invalid values are a 400 (``invalid_query_parameters``)."""

    action = django_filters.CharFilter(field_name="action", max_length=100)
    actor = django_filters.UUIDFilter(field_name="actor")
    outcome = django_filters.ChoiceFilter(field_name="outcome", choices=AuditOutcome.choices)
    created_after = django_filters.IsoDateTimeFilter(field_name="created_at", lookup_expr="gte")
    created_before = django_filters.IsoDateTimeFilter(field_name="created_at", lookup_expr="lt")

    class Meta:
        model = AuditLog
        fields: list[str] = []
