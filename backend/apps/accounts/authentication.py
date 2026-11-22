"""DRF authentication: ``Authorization: Bearer <access token>`` checked against the server-side
session on every request (ADR-0004)."""

from typing import Any

from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.request import Request

from apps.core.request_context import bind_request_context

from .sessions import AccessContext, authenticate_access_token
from .tokens import InvalidTokenError

AUTH_SCHEME = "Bearer"
WWW_AUTHENTICATE = f'{AUTH_SCHEME} realm="api"'


class SessionJWTAuthentication(BaseAuthentication):
    def authenticate(self, request: Request) -> tuple[Any, AccessContext] | None:
        header = get_authorization_header(request).split()
        if not header:
            return None
        if header[0].lower() != AUTH_SCHEME.lower().encode():
            return None
        if len(header) != 2:  # noqa: PLR2004 - "Bearer <token>"
            raise exceptions.AuthenticationFailed()
        try:
            raw = header[1].decode("ascii")
            context = authenticate_access_token(raw)
        except (UnicodeDecodeError, InvalidTokenError) as exc:
            raise exceptions.AuthenticationFailed() from exc
        bind_request_context(user_id=str(context.user.pk), session_id=str(context.session.id))
        return context.user, context

    def authenticate_header(self, request: Request) -> str:
        return WWW_AUTHENTICATE
