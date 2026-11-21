"""Pagination boundaries, filtering and ordering allowlists (isolated fixture model)."""

from collections.abc import Callable
from typing import Any

import pytest
from django.test import Client

from tests.fixtures_app.models import Widget

pytestmark = [pytest.mark.urls("tests.fixtures_app.urls"), pytest.mark.django_db]

AssertProblem = Callable[..., dict[str, Any]]
URL = "/test-api/widgets/"


@pytest.fixture
def client() -> Client:
    return Client(raise_request_exception=False)


def _assert_configuration_error_logged(json_logs: Any, fragment: str) -> None:
    """Misconfigured views fail closed: generic 500 to the client, details only in server logs."""
    [event] = json_logs.events("request.unhandled_exception")
    assert "ImproperlyConfigured" in event["exception"]
    assert fragment in event["exception"]


def _make(count: int, **overrides: Any) -> list[Widget]:
    return Widget.objects.bulk_create(
        [
            Widget(
                name=overrides.get("name", f"w{i:03d}"),
                category=overrides.get("category", "even" if i % 2 == 0 else "odd"),
                quantity=i,
            )
            for i in range(count)
        ]
    )


class TestPaginationShape:
    def test_default_page_size_is_25(self, client: Client) -> None:
        _make(30)
        body = client.get(URL).json()

        assert list(body) == [
            "count",
            "page",
            "page_size",
            "total_pages",
            "next",
            "previous",
            "results",
        ]
        assert body["count"] == 30
        assert body["page"] == 1
        assert body["page_size"] == 25
        assert body["total_pages"] == 2
        assert len(body["results"]) == 25
        assert body["previous"] is None
        assert body["next"].endswith("?page=2")

    def test_last_page(self, client: Client) -> None:
        _make(30)
        body = client.get(URL, {"page": 2}).json()

        assert len(body["results"]) == 5
        assert body["next"] is None
        assert body["previous"] is not None

    def test_empty_collection_returns_empty_first_page(self, client: Client) -> None:
        body = client.get(URL).json()
        assert body == {
            "count": 0,
            "page": 1,
            "page_size": 25,
            "total_pages": 1,
            "next": None,
            "previous": None,
            "results": [],
        }


class TestPaginationBoundaries:
    @pytest.mark.parametrize(
        ("requested", "effective"), [("1", 1), ("100", 100), ("101", 100), ("100000", 100)]
    )
    def test_page_size_is_capped_at_100(
        self, client: Client, requested: str, effective: int
    ) -> None:
        _make(120)
        body = client.get(URL, {"page_size": requested}).json()

        assert body["page_size"] == effective
        assert len(body["results"]) == effective

    # "\uff11" is FULLWIDTH DIGIT ONE: str.isdigit() accepts it, the pagination must not.
    @pytest.mark.parametrize("value", ["0", "-1", "abc", "1.5", " 2", "", "\uff11"])
    def test_invalid_page_size_is_rejected(
        self, client: Client, assert_problem: AssertProblem, value: str
    ) -> None:
        body = assert_problem(
            client.get(URL, {"page_size": value}), 400, "invalid_query_parameters"
        )
        assert body["errors"] == [
            {"detail": "Must be a positive integer.", "code": "invalid", "parameter": "page_size"}
        ]

    @pytest.mark.parametrize("value", ["0", "-3", "last", "x"])
    def test_invalid_page_number_is_rejected(
        self, client: Client, assert_problem: AssertProblem, value: str
    ) -> None:
        body = assert_problem(client.get(URL, {"page": value}), 400, "invalid_query_parameters")
        assert body["errors"][0]["parameter"] == "page"

    def test_both_invalid_parameters_are_reported(
        self, client: Client, assert_problem: AssertProblem
    ) -> None:
        body = assert_problem(
            client.get(URL, {"page": "0", "page_size": "x"}), 400, "invalid_query_parameters"
        )
        assert {e["parameter"] for e in body["errors"]} == {"page", "page_size"}

    def test_page_beyond_last_is_not_found(
        self, client: Client, assert_problem: AssertProblem
    ) -> None:
        _make(3)
        body = assert_problem(client.get(URL, {"page": 2}), 404, "page_not_found")
        assert body["detail"] == "The requested page does not exist."


class TestFiltering:
    def test_allowlisted_filter_applies(self, client: Client) -> None:
        _make(10)
        body = client.get(URL, {"category": "odd"}).json()

        assert body["count"] == 5
        assert {w["category"] for w in body["results"]} == {"odd"}

    def test_unlisted_parameters_are_ignored(self, client: Client) -> None:
        _make(4)
        assert client.get(URL, {"name": "w001"}).json()["count"] == 4

    def test_invalid_filter_value_is_rejected(
        self, client: Client, assert_problem: AssertProblem
    ) -> None:
        body = assert_problem(
            client.get(URL, {"quantity": "many"}), 400, "invalid_query_parameters"
        )
        assert body["errors"] == [
            {"detail": "Enter a number.", "code": "invalid", "parameter": "quantity"}
        ]

    def test_filter_all_fields_is_rejected(
        self, client: Client, assert_problem: AssertProblem, json_logs: Any
    ) -> None:
        assert_problem(client.get("/test-api/widgets-all/"), 500, "internal_error")
        _assert_configuration_error_logged(json_logs, "explicit list")


class TestOrdering:
    def test_default_ordering_is_stable_with_duplicates(self, client: Client) -> None:
        widgets = _make(40, name="same")  # identical sort keys: the pk tie-breaker decides
        expected = sorted(str(w.id) for w in widgets)

        page1 = client.get(URL, {"page_size": 20}).json()["results"]
        page2 = client.get(URL, {"page_size": 20, "page": 2}).json()["results"]

        assert [w["id"] for w in page1 + page2] == expected

    def test_requested_ordering(self, client: Client) -> None:
        _make(5)
        results = client.get(URL, {"ordering": "-quantity"}).json()["results"]
        assert [w["quantity"] for w in results] == [4, 3, 2, 1, 0]

    def test_multiple_ordering_fields(self, client: Client) -> None:
        Widget.objects.bulk_create(
            [
                Widget(name=n, category="c", quantity=q)
                for n, q in [("y", 1), ("x", 1), ("y", 2), ("x", 2)]
            ]
        )
        results = client.get(URL, {"ordering": "name,-quantity"}).json()["results"]
        assert [(w["name"], w["quantity"]) for w in results] == [
            ("x", 2),
            ("x", 1),
            ("y", 2),
            ("y", 1),
        ]

    def test_explicit_pk_ordering_is_not_duplicated(self, client: Client) -> None:
        widgets = _make(3)
        results = client.get(URL, {"ordering": "-created_at"}).json()["results"]
        assert len(results) == len(widgets)

    @pytest.mark.parametrize("value", ["category_secret", "name,unknown", "-password", "__str__"])
    def test_unlisted_ordering_is_rejected(
        self, client: Client, assert_problem: AssertProblem, value: str
    ) -> None:
        body = assert_problem(client.get(URL, {"ordering": value}), 400, "invalid_query_parameters")
        assert body["errors"][0]["parameter"] == "ordering"

    def test_blank_ordering_uses_default(self, client: Client) -> None:
        _make(3)
        assert client.get(URL, {"ordering": " "}).status_code == 200

    def test_missing_ordering_fields_is_a_configuration_error(
        self, client: Client, assert_problem: AssertProblem, json_logs: Any
    ) -> None:
        assert_problem(client.get("/test-api/widgets-no-ordering-fields/"), 500, "internal_error")
        _assert_configuration_error_logged(json_logs, "ordering_fields")

    def test_missing_default_ordering_is_a_configuration_error(
        self, client: Client, assert_problem: AssertProblem, json_logs: Any
    ) -> None:
        assert_problem(client.get("/test-api/widgets-no-default-ordering/"), 500, "internal_error")
        _assert_configuration_error_logged(json_logs, "default ordering")


def test_category_tie_breaker_helper_respects_existing_pk() -> None:
    from apps.core.api.filtering import StableOrderingFilter  # noqa: PLC0415

    assert StableOrderingFilter._with_tie_breaker(["name", "-id"], Widget) == ["name", "-id"]
    assert StableOrderingFilter._with_tie_breaker(["name"], Widget) == ["name", "pk"]


def test_paginated_response_schema_shape() -> None:
    from apps.core.api.pagination import StandardPagination  # noqa: PLC0415

    schema = StandardPagination().get_paginated_response_schema({"type": "array"})
    assert schema["required"] == [
        "count",
        "page",
        "page_size",
        "total_pages",
        "next",
        "previous",
        "results",
    ]
    assert schema["properties"]["results"] == {"type": "array"}
