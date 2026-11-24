"""Shared helpers for invitation tests (test-only module)."""

import re
from typing import Any

from django.core import mail
from django.test import Client

from apps.accounts.models import User
from apps.organizations.invitation_outbox import deliver_due
from apps.organizations.models import Invitation
from apps.organizations.tests.conftest import bearer

TOKEN_IN_LINK = re.compile(r"#token=([A-Za-z0-9_-]{43})")
PREVIEW = "/api/v1/invitations/{token}/"
ACCEPT = "/api/v1/invitations/{token}/accept/"
NEW_PASSWORD = "Correct-Horse-Battery-Staple-42"


def deliver() -> dict[str, str]:
    """Run the delivery command once; return {recipient address: token} for the new messages."""
    before = len(mail.outbox)
    deliver_due(batch_size=100)
    tokens: dict[str, str] = {}
    for message in mail.outbox[before:]:
        match = TOKEN_IN_LINK.search(str(message.body))
        assert match is not None, message.body
        tokens[message.to[0]] = match.group(1)
    return tokens


def token_for(invitation: Invitation) -> str:
    """Deliver pending emails and return the token emailed for ``invitation``."""
    tokens = deliver()
    assert invitation.email in tokens, (invitation.email, list(tokens))
    return tokens[invitation.email]


def preview(token: str, user: User | None = None) -> Any:
    headers = bearer(user) if user is not None else {}
    return Client().get(PREVIEW.format(token=token), **headers)


def accept(
    token: str,
    body: dict[str, Any] | None = None,
    user: User | None = None,
    *,
    raise_errors: bool = True,
) -> Any:
    headers = bearer(user) if user is not None else {}
    return Client(raise_request_exception=raise_errors).post(
        ACCEPT.format(token=token), body or {}, content_type="application/json", **headers
    )


def new_account_body(full_name: str = "New Person") -> dict[str, str]:
    return {"full_name": full_name, "password": NEW_PASSWORD}
