"""AEMS-007: public-endpoint allowlist enforcement (static checks and runtime guard)."""

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest
from django.conf import settings
from django.test import Client, RequestFactory
from rest_framework.request import Request
from rest_framework.views import APIView

from apps.core.api.permissions import (
    PublicAccessGuard,
    is_allowlisted_public_request,
    is_authenticated,
    named_callbacks,
)
from apps.core.checks import find_public_endpoint_violations
from tests.fixtures_app.urls import PUBLIC_FIXTURE_NAMES

AssertProblem = Callable[..., dict[str, Any]]


def _messages(urlconf: str) -> list[tuple[str, str]]:
    return sorted((m.id or "", m.msg) for m in find_public_endpoint_violations(urlconf))


@pytest.fixture(scope="module")
def found() -> list[tuple[str, str]]:
    return _messages("apps.core.tests.urls_violations")


class TestStaticChecks:
    def test_project_urlconf_is_clean(self) -> None:
        assert find_public_endpoint_violations() == []

    def test_unlisted_public_endpoint(self, found: list[tuple[str, str]]) -> None:
        assert any(i == "core.E001" and "'unlisted-public'" in m for i, m in found)

    def test_bare_allow_any_and_custom_subclass(self, found: list[tuple[str, str]]) -> None:
        e002 = [m for i, m in found if i == "core.E002"]
        assert any("nested:bare-allow-any" in m for m in e002)
        assert any("custom-allow-any" in m for m in e002)
        assert any("<unnamed route" in m for m in e002)

    def test_empty_permission_classes(self, found: list[tuple[str, str]]) -> None:
        e003 = [m for i, m in found if i == "core.E003"]
        assert any("'empty-permissions'" in m for m in e003)
        assert any("'actions-emptied'" in m for m in e003)  # ViewSet action override

    def test_viewset_action_specific_allow_any(self, found: list[tuple[str, str]]) -> None:
        assert any(i == "core.E002" and "'actions-opened'" in m for i, m in found)
        assert any(i == "core.E001" and "'actions-opened'" in m for i, m in found)

    def test_unguarded_drf_view(self, found: list[tuple[str, str]]) -> None:
        e004 = [m for i, m in found if i == "core.E004"]
        assert e004 == ["DRF view UnguardedView (unguarded) does not use PublicAccessGuard."]

    def test_duplicate_drf_url_names(self, found: list[tuple[str, str]]) -> None:
        e005 = [m for i, m in found if i == "core.E005"]
        assert e005 == ["URL name 'denied' is registered 2 times."]

    def test_compliant_views_are_not_reported(self, found: list[tuple[str, str]]) -> None:
        assert not any("plain-django" in m for _, m in found)
        assert not any("'actions-list'" in m for _, m in found)

    def test_fixture_urlconf_flags_its_deliberate_violations(self) -> None:
        found = _messages("tests.fixtures_app.urls")
        ids = {i for i, _ in found}
        assert ids == {"core.E001", "core.E002", "core.E003", "core.E004"}
        assert any("UnguardedPublicView" in m for i, m in found if i == "core.E004")

    def test_test_allowlist_matches_fixture_names(self) -> None:
        from config.settings import base  # noqa: PLC0415

        extra = set(settings.API_PUBLIC_ENDPOINTS) - set(base.API_PUBLIC_ENDPOINTS)
        assert extra == set(PUBLIC_FIXTURE_NAMES)


@pytest.mark.urls("tests.fixtures_app.urls")
class TestRuntimeGuard:
    @pytest.mark.parametrize(
        "path",
        [
            "/test-api/empty-permissions/",  # permission_classes = []
            "/test-api/custom-permissive/",  # custom has_permission -> True
            "/test-api/dynamic/",  # get_permissions() -> AllowAny
            "/test-api/actions/unsafe/",  # @action(permission_classes=[AllowAny])
            "/test-api/actions/dynamic/",  # action-specific get_permissions()
        ],
    )
    def test_anonymous_access_to_non_allowlisted_endpoint_is_blocked(
        self, path: str, assert_problem: AssertProblem, json_logs: Any
    ) -> None:
        response = Client().get(path)

        # Authentication exists (Batch 3): unauthenticated access is challenged with 401.
        body = assert_problem(response, 401, "not_authenticated")
        assert response["WWW-Authenticate"] == 'Bearer realm="api"'
        assert "reached" not in body
        [event] = json_logs.events("security.public_access_blocked")
        assert event["level"] == "error"

    def test_unlisted_public_endpoint_is_refused_by_the_permission_itself(
        self, assert_problem: AssertProblem, json_logs: Any
    ) -> None:
        assert_problem(Client().get("/test-api/unlisted-public/"), 401, "not_authenticated")
        [event] = json_logs.events("security.public_endpoint_not_allowlisted")
        assert event["view_name"] == "test-unlisted-public"

    def test_allowlisted_viewset_action_is_reachable(self) -> None:
        response = Client().get("/test-api/actions/")
        assert response.status_code == 200
        assert response.json() == {"reached": "list"}

    def test_unguarded_but_allowlisted_view_still_checks_allowlist(self) -> None:
        # Flagged statically (core.E004); at runtime PublicEndpoint still enforces the allowlist.
        assert Client().get("/test-api/unguarded/").status_code == 200

    def test_project_public_endpoint_remains_reachable(self) -> None:
        assert Client().get("/api/v1/").status_code == 200


@pytest.mark.urls("tests.fixtures_app.urls_duplicate")
def test_duplicate_url_name_cannot_borrow_an_allowlist_entry(assert_problem: AssertProblem) -> None:
    # "test-echo" is allowlisted but registered twice: fail closed for BOTH routes.
    assert_problem(Client().get("/test-api/echo/"), 401, "not_authenticated")
    assert_problem(Client().get("/test-api/echo-shadow/"), 401, "not_authenticated")


class TestRuntimeHelpers:
    def test_request_without_resolver_match_is_not_allowlisted(self) -> None:
        assert is_allowlisted_public_request(RequestFactory().get("/")) is False

    def test_unnamed_match_is_not_allowlisted(self) -> None:
        request = SimpleNamespace(resolver_match=SimpleNamespace(url_name=None, view_name="x"))
        assert is_allowlisted_public_request(request) is False

    def test_named_callbacks_maps_each_name_once(self) -> None:
        mapping = named_callbacks(settings.ROOT_URLCONF)
        assert len(mapping["api-v1:root"]) == 1

    @pytest.mark.parametrize(
        ("user", "expected"),
        [
            (None, False),
            (SimpleNamespace(is_authenticated=False), False),
            (SimpleNamespace(is_authenticated=True), True),
            (object(), False),
        ],
    )
    def test_is_authenticated(self, user: Any, expected: bool) -> None:
        assert is_authenticated(user) is expected

    def test_guard_lets_authenticated_requests_through_to_normal_permissions(self) -> None:
        class Guarded(PublicAccessGuard, APIView):
            permission_classes: list[Any] = []

        request = Request(RequestFactory().get("/anything/"))
        request.user = SimpleNamespace(is_authenticated=True)  # type: ignore[assignment]
        Guarded().check_permissions(request)  # does not raise: allowlist applies to anonymous only
