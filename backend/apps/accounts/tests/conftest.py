"""Shared fixtures for accounts tests."""

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from django.test import Client

from apps.accounts.models import User
from apps.core import security_events

PASSWORD = "Correct-Horse-Battery-42"
LOGIN_URL = "/api/v1/auth/login/"
REFRESH_URL = "/api/v1/auth/token/refresh/"
LOGOUT_URL = "/api/v1/auth/logout/"
CSRF_URL = "/api/v1/auth/csrf/"
ME_URL = "/api/v1/auth/me/"
SESSIONS_URL = "/api/v1/auth/sessions/"
REFRESH_COOKIE = "aems_refresh"


@pytest.fixture
def make_user(db: Any) -> Callable[..., User]:
    counter = {"n": 0}

    def _make(email: str | None = None, password: str = PASSWORD, **extra: Any) -> User:
        counter["n"] += 1
        extra.setdefault("full_name", f"Test User {counter['n']}")
        return User.objects.create_user(
            email or f"user{counter['n']}@example.org", password, **extra
        )

    return _make


@pytest.fixture
def user(make_user: Callable[..., User]) -> User:
    return make_user("alice@example.org")


@dataclass
class Session:
    client: Client
    access_token: str

    @property
    def auth(self) -> dict[str, str]:
        return {"HTTP_AUTHORIZATION": f"Bearer {self.access_token}"}

    @property
    def refresh_token(self) -> str:
        return self.client.cookies[REFRESH_COOKIE].value

    def csrf_headers(self) -> dict[str, Any]:
        if "csrftoken" not in self.client.cookies:
            self.client.get(CSRF_URL)
        return {
            "HTTP_X_CSRFTOKEN": self.client.cookies["csrftoken"].value,
            "HTTP_ORIGIN": "http://testserver",
        }

    def refresh(self) -> Any:
        return self.client.post(REFRESH_URL, **self.csrf_headers())


def do_login(email: str, password: str = PASSWORD, *, client: Client | None = None) -> Session:
    client = client or Client(enforce_csrf_checks=True)
    response = client.post(
        LOGIN_URL, {"email": email, "password": password}, content_type="application/json"
    )
    assert response.status_code == 200, response.content
    return Session(client=client, access_token=response.json()["access_token"])


@pytest.fixture
def login() -> Callable[..., Session]:
    return do_login


@pytest.fixture
def events() -> Iterator[list[security_events.SecurityEvent]]:
    captured: list[security_events.SecurityEvent] = []
    unregister = security_events.register_sink(captured.append)
    yield captured
    unregister()


def event_names(captured: list[security_events.SecurityEvent]) -> list[str]:
    return [event.name for event in captured]
