"""Input validation and error-disclosure attacks against the API (plan §8, §9.2, ADR-0019).

Includes the regression tests for review finding AEMS-019: JSON request bodies were not limited by
``DATA_UPLOAD_MAX_MEMORY_SIZE`` (DRF parses the stream directly), and deeply nested JSON raised an
unhandled ``RecursionError`` (500).
"""

import json
from collections.abc import Callable
from typing import Any, cast

import pytest
from django.conf import settings
from django.test import Client, override_settings

from apps.accounts.models import User
from apps.audit.models import AuditLog
from apps.core.api.parsers import MAX_JSON_DEPTH
from apps.organizations.models import Organization
from apps.organizations.tests.conftest import Api, error_fields
from apps.rbac.models import Role
from apps.rbac.tests.conftest import Team, role, url

pytestmark = pytest.mark.django_db

LOGIN = "/api/v1/auth/login/"


def _post_raw(
    path: str, body: bytes | str, content_type: str = "application/json", **extra: Any
) -> Any:
    return Client().generic("POST", path, body, content_type=content_type, **extra)


# --------------------------------------------------------------- AEMS-019: body size and depth
class TestRequestBodyLimits:
    def test_rest_framework_uses_the_bounded_parser_only(self) -> None:
        assert settings.REST_FRAMEWORK["DEFAULT_PARSER_CLASSES"] == [
            "apps.core.api.parsers.BoundedJSONParser"
        ]

    def test_oversized_json_body_is_rejected_with_413(self, assert_problem: Any) -> None:
        cap = settings.DATA_UPLOAD_MAX_MEMORY_SIZE
        body = json.dumps({"email": "a@example.org", "password": "x" * (cap + 10)})
        response = _post_raw(LOGIN, body)
        assert_problem(response, 413, "request_too_large")
        assert not AuditLog.objects.filter(action="auth.login.failed").exists()

    def test_body_at_the_cap_is_parsed(self) -> None:
        cap = settings.DATA_UPLOAD_MAX_MEMORY_SIZE
        prefix = '{"email": "a@example.org", "password": "'
        body = prefix + "x" * (cap - len(prefix) - 2) + '"}'
        assert len(body.encode()) == cap
        # Parsed and validated normally (the password exceeds the field limit): 400, not 413.
        assert _post_raw(LOGIN, body).status_code == 400

    def test_real_wsgi_request_is_413_not_500(self) -> None:
        """Through Django's WSGI handler, as gunicorn calls it (not the test client)."""
        import io  # noqa: PLC0415

        from django.core.handlers.wsgi import WSGIHandler  # noqa: PLC0415

        def call(body: bytes) -> str:
            environ = {
                "REQUEST_METHOD": "POST",
                "PATH_INFO": LOGIN,
                "SERVER_NAME": "testserver",
                "SERVER_PORT": "80",
                "HTTP_HOST": "testserver",
                "wsgi.url_scheme": "http",
                "CONTENT_TYPE": "application/json",
                "CONTENT_LENGTH": str(len(body)),
                "wsgi.input": io.BytesIO(body),
                "wsgi.errors": io.StringIO(),
                "REMOTE_ADDR": "198.51.100.7",
            }
            seen: dict[str, str] = {}

            def start_response(status: str, _headers: Any, _exc: Any = None) -> Any:
                seen["status"] = status

            b"".join(WSGIHandler()(environ, cast(Any, start_response)))
            return seen["status"]

        cap = settings.DATA_UPLOAD_MAX_MEMORY_SIZE
        assert call(b'{"password": "' + b"x" * cap + b'"}').startswith("413")
        assert call(b"[" * 100_000 + b"]" * 100_000).startswith("400")

    def test_parser_depth_check_is_iterative(self) -> None:
        from apps.core.api.parsers import depth_exceeds  # noqa: PLC0415

        deep: Any = []
        for _ in range(50_000):
            deep = [deep]
        assert depth_exceeds(deep, MAX_JSON_DEPTH)
        assert not depth_exceeds({"a": [1, {"b": 2}]}, 3)
        assert depth_exceeds({"a": [1, {"b": [2]}]}, 3)

    @override_settings(DATA_UPLOAD_MAX_MEMORY_SIZE=64)
    def test_cap_follows_the_setting(self, assert_problem: Any) -> None:
        assert_problem(_post_raw(LOGIN, json.dumps({"email": "a" * 80})), 413, "request_too_large")

    @pytest.mark.parametrize("depth", [MAX_JSON_DEPTH + 1, 5_000, 200_000])
    def test_excessively_nested_json_is_a_client_error(
        self, depth: int, assert_problem: Any
    ) -> None:
        body = "[" * depth + "]" * depth
        assert_problem(_post_raw(LOGIN, body), 400, "parse_error")

    def test_nesting_within_the_limit_is_accepted(self) -> None:
        nested: Any = "leaf"
        for _ in range(MAX_JSON_DEPTH - 1):
            nested = {"k": nested}
        response = _post_raw(LOGIN, json.dumps({"email": "a@example.org", "x": nested}))
        assert response.status_code == 400  # validation (missing password), not a parse error
        assert "password" in error_fields(response)

    def test_unparseable_and_non_standard_json(self, assert_problem: Any) -> None:
        for body in ("{", '{"a": NaN}', '{"a": Infinity}', "\xff\xfe", '{"a": 1}garbage'):
            assert_problem(_post_raw(LOGIN, body.encode("latin-1")), 400, "parse_error")


# --------------------------------------------------------------- content types and methods
class TestContentTypes:
    @pytest.mark.parametrize(
        "content_type",
        [
            "text/plain",
            "application/x-www-form-urlencoded",
            "multipart/form-data; boundary=x",
            "application/xml",
        ],
    )
    def test_only_json_is_accepted(self, content_type: str, assert_problem: Any) -> None:
        """Form and text bodies are CORS "simple" requests; they must never be processed."""
        body = "email=a%40example.org&password=x"
        assert_problem(_post_raw(LOGIN, body, content_type), 415, "unsupported_media_type")

    def test_json_with_charset_is_accepted(self) -> None:
        response = _post_raw(LOGIN, "{}", "application/json; charset=utf-8")
        assert response.status_code == 400

    @pytest.mark.parametrize("method", ["PUT", "POST", "DELETE", "TRACE", "PROPFIND"])
    def test_undeclared_methods_never_succeed(
        self, team: Team, as_user: Callable[..., Api], method: str
    ) -> None:
        """Tenant authorization runs before dispatch: an undeclared action is denied (default
        deny, 403) even for the Owner, and unknown methods never reach a handler."""
        before = Organization.objects.values().get(pk=team.org.pk)
        response = Client().generic(
            method,
            url(team.org),
            "{}",
            content_type="application/json",
            **as_user(team.owner).headers,
        )
        assert response.status_code in (403, 405)
        assert Organization.objects.values().get(pk=team.org.pk) == before

    def test_unsupported_method_on_an_authenticated_route_is_405(self, team: Team) -> None:
        response = Api(as_headers(team.owner)).put("/api/v1/auth/me/", {"full_name": "X"})
        assert response.status_code == 405
        assert "PUT" not in response["Allow"]


# --------------------------------------------------------------- field-level validation
class TestFieldValidation:
    def test_unexpected_fields_are_never_applied(
        self, team: Team, as_user: Callable[..., Api]
    ) -> None:
        before = Organization.objects.values().get(pk=team.org.pk)
        response = as_user(team.owner).patch(
            url(team.org),
            {"status": "suspended", "slug": "hijack", "created_by": str(team.outsider.pk)},
        )
        assert response.status_code in (200, 400)
        assert Organization.objects.values().get(pk=team.org.pk) == before

    def test_privilege_fields_cannot_be_set_on_the_profile(self, team: Team) -> None:
        response = Api(as_headers(team.member)).patch(
            "/api/v1/auth/me/", {"is_staff": True, "is_superuser": True, "email": "x@evil.test"}
        )
        assert response.status_code in (200, 400)
        fresh = User.objects.get(pk=team.member.pk)
        assert (fresh.is_staff, fresh.is_superuser, fresh.email) == (
            False,
            False,
            "member@example.org",
        )

    @pytest.mark.parametrize(
        "body",
        [
            {"email": "x" * 300 + "@example.org", "role_ids": []},
            {"email": "not-an-email", "role_ids": []},
            {"email": ["a@example.org"], "role_ids": []},
            {"email": {"$ne": ""}, "role_ids": []},
            {"email": "n@example.org", "role_ids": "all"},
            {"email": "n@example.org", "role_ids": ["not-a-uuid"]},
            {"email": "n@example.org", "role_ids": [1, 2]},
            {"email": "n@example.org", "role_ids": [None]},
        ],
    )
    def test_invalid_invitation_input_is_400(
        self, team: Team, as_user: Callable[..., Api], body: dict[str, Any]
    ) -> None:
        response = as_user(team.owner).post(url(team.org, "invitations/"), body)
        assert response.status_code == 400, response.content
        assert response.json()["code"] in {"validation_error", "invalid"}

    @pytest.mark.parametrize(
        "body",
        [
            {"name": "x" * 1000, "permissions": []},
            {"name": "", "permissions": []},
            {"name": "R", "permissions": ["no.such.permission"]},
            {"name": "R", "permissions": "roles.manage"},
            {"name": ["R"], "permissions": []},
            {"name": "R", "permissions": [{"code": "roles.manage"}]},
        ],
    )
    def test_invalid_role_input_is_400(
        self, team: Team, as_user: Callable[..., Api], body: dict[str, Any]
    ) -> None:
        count = Role.objects.count()
        response = as_user(team.owner).post(url(team.org, "roles/"), body)
        assert response.status_code == 400, response.content
        assert Role.objects.count() == count

    @pytest.mark.parametrize("status", ["deleted", "owner", "", None, 1, ["suspended"]])
    def test_invalid_membership_status_transitions(
        self, team: Team, as_user: Callable[..., Api], status: Any
    ) -> None:
        target = team.membership(team.member)
        response = as_user(team.owner).patch(
            url(team.org, f"members/{target.pk}/"), {"status": status}
        )
        assert response.status_code == 400
        target.refresh_from_db()
        assert target.status == "active"

    def test_type_confusion_in_role_assignment(
        self, team: Team, as_user: Callable[..., Api]
    ) -> None:
        target = team.membership(team.member)
        bodies: list[Any] = [
            {"role_ids": str(role(team.org, "admin").pk)},
            {"role_ids": {"0": "x"}},
            [],
        ]
        for body in bodies:
            response = as_user(team.owner).put(url(team.org, f"members/{target.pk}/roles/"), body)
            assert response.status_code == 400, response.content
        from apps.rbac.models import MembershipRole  # noqa: PLC0415

        held = MembershipRole.objects.filter(membership=target)
        assert set(held.values_list("role__system_key", flat=True)) == {"member"}


def as_headers(user: User) -> dict[str, Any]:
    from apps.organizations.tests.conftest import bearer  # noqa: PLC0415

    return bearer(user)


# --------------------------------------------------------------- pagination, filters, ordering
class TestQueryParameters:
    @pytest.mark.parametrize(
        "query",
        [
            "page_size=-1",
            "page_size=abc",
            "page=0",
            "page=-5",
            "page=99999999999999999999",
            "ordering=password",
            "ordering=user__password",
            "ordering=-user__email,__class__",
            "status=bogus",
            "unknown_filter=1",
        ],
    )
    def test_invalid_query_parameters_never_500(
        self, team: Team, as_user: Callable[..., Api], query: str
    ) -> None:
        response = as_user(team.owner).get(url(team.org, f"members/?{query}"))
        assert response.status_code in (200, 400, 404), response.content
        if response.status_code == 200:
            emails = [m["user"]["email"] for m in response.json()["results"]]
            assert all(e.endswith("@example.org") for e in emails)

    def test_page_size_is_capped(self, team: Team, as_user: Callable[..., Api]) -> None:
        response = as_user(team.owner).get(url(team.org, "members/?page_size=100000"))
        assert response.status_code in (200, 400)
        if response.status_code == 200:
            assert len(response.json()["results"]) <= 100

    @pytest.mark.parametrize(
        "query",
        [
            "cursor=garbage",
            "actor=not-a-uuid",
            "created_after=not-a-date",
            "ordering=metadata",
            "organization=" + "00000000-0000-0000-0000-000000000000",
        ],
    )
    def test_audit_query_tampering_is_rejected_or_harmless(
        self, team: Team, as_user: Callable[..., Api], query: str
    ) -> None:
        AuditLog.objects.create(
            action="organization.updated", outcome="success", organization=team.other
        )
        response = as_user(team.owner).get(url(team.org, f"audit-logs/?{query}"))
        assert response.status_code in (200, 400, 404), response.content
        if response.status_code == 200:
            assert {r["organization"] for r in response.json()["results"]} <= {str(team.org.pk)}


@pytest.mark.parametrize(
    "position",
    [
        "2024-01-01",
        "2024-01-01T00:00:00",
        "not-a-date",
        "2024-13-45T99:99:99+00:00",
        "",
        "' OR 1=1",
    ],
)
def test_tampered_audit_cursor_positions_are_404(
    team: Team, as_user: Callable[..., Api], position: str, assert_problem: Any
) -> None:
    """AEMS-020: a decoded and re-encoded cursor with a naive or invalid timestamp is 404."""
    import base64  # noqa: PLC0415
    from urllib.parse import quote, urlencode  # noqa: PLC0415

    cursor = base64.b64encode(urlencode({"p": position}).encode()).decode()
    response = as_user(team.owner).get(url(team.org, f"audit-logs/?cursor={quote(cursor)}"))
    assert_problem(response, 404, "not_found")


def test_genuine_audit_cursors_still_page(team: Team, as_user: Callable[..., Api]) -> None:
    for _ in range(3):
        AuditLog.objects.create(
            action="organization.updated", outcome="success", organization=team.org
        )
    client = as_user(team.owner)
    first = client.get(url(team.org, "audit-logs/?page_size=1")).json()
    assert first["next"]
    second = client.get(first["next"].replace("http://testserver", ""))
    assert second.status_code == 200
    assert second.json()["results"][0]["id"] != first["results"][0]["id"]


# --------------------------------------------------------------- error disclosure
class TestErrorDisclosure:
    def test_unexpected_exception_is_a_generic_500(
        self,
        team: Team,
        as_user: Callable[..., Api],
        monkeypatch: pytest.MonkeyPatch,
        assert_problem: Any,
    ) -> None:
        from apps.organizations.api import views  # noqa: PLC0415

        def explode(*_args: Any, **_kwargs: Any) -> Any:
            msg = "SELECT secret FROM table WHERE password='hunter2' /srv/app/settings.py"
            raise RuntimeError(msg)

        monkeypatch.setattr(views.OrganizationMembershipView, "get", explode)
        client = Client(raise_request_exception=False)
        response = client.get(url(team.org, "me/"), **as_user(team.owner).headers)
        body = assert_problem(response, 500, "internal_error")
        text = response.content.decode()
        for leak in ("SELECT", "hunter2", "/srv/", "RuntimeError", "Traceback"):
            assert leak not in text
        assert set(body) <= {"type", "title", "status", "detail", "code", "request_id"}

    def test_404_for_unknown_paths_is_problem_json(self, assert_problem: Any) -> None:
        response = Client().get("/api/v1/does-not-exist/<script>/")
        assert_problem(response, 404, "not_found")
        assert "<script>" not in response.content.decode()

    def test_validation_errors_do_not_echo_sensitive_values(self, team: Team) -> None:
        secret = "Sup3r-Secret-Value-123!"
        response = Client().post(
            "/api/v1/auth/password/reset/confirm/",
            {"uid": "x", "token": secret, "new_password": ["not", "a", "string", secret]},
            content_type="application/json",
        )
        assert response.status_code == 400
        assert secret not in response.content.decode()
