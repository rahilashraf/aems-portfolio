"""Authentication API (`/api/v1/auth/`, ADR-0004, ADR-0012).

Public (allowlisted in ``API_PUBLIC_ENDPOINTS``): csrf, login, token refresh, logout, password reset
request and confirm. Everything else requires a valid access token whose server-side session is
active. Cookie-authenticated operations (refresh; logout when the refresh cookie is present) enforce
Django CSRF checks.
"""

from typing import Any

from django.conf import settings
from django.db import transaction
from django.middleware.csrf import get_token
from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import exceptions, status
from rest_framework.authentication import get_authorization_header
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from apps.accounts import services
from apps.accounts.authentication import AUTH_SCHEME, WWW_AUTHENTICATE
from apps.accounts.cookies import clear_refresh_cookie, refresh_cookie_value, set_refresh_cookie
from apps.accounts.csrf import enforce_csrf
from apps.accounts.models import AuthSession, RevokeReason, User
from apps.accounts.sessions import (
    AccessContext,
    IssuedTokens,
    RotationOutcome,
    authenticate_access_token,
    revoke_session,
    revoke_user_sessions,
    rotate,
)
from apps.accounts.tokens import InvalidTokenError, decode_refresh_token
from apps.core.api.openapi import PROBLEM_401_EXTENSION
from apps.core.api.permissions import PublicEndpoint
from apps.core.api.views import AemsAPIView, AemsGenericAPIView
from apps.core.net import client_ip
from apps.core.security_events import record_security_event

from . import serializers as s

TAG = "auth"
REFRESH_COOKIE_PARAMETER = OpenApiParameter(
    name="aems_refresh",
    location=OpenApiParameter.COOKIE,
    required=False,
    description="HttpOnly refresh-token cookie (Path=/api/v1/auth/). Requires X-CSRFToken.",
)
CSRF_HEADER_PARAMETER = OpenApiParameter(
    name="X-CSRFToken",
    location=OpenApiParameter.HEADER,
    required=False,
    description="Value of the csrftoken cookie (from GET /api/v1/auth/csrf/).",
)


def _access_lifetime_seconds() -> int:
    return int(settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds())


def _token_body(tokens: IssuedTokens) -> dict[str, Any]:
    return {
        "access_token": tokens.access_token,
        "token_type": AUTH_SCHEME,
        "expires_in": _access_lifetime_seconds(),
    }


def _user(request: Request) -> User:
    if not isinstance(request.user, User):  # guaranteed by IsAuthenticated
        raise exceptions.NotAuthenticated()
    return request.user


def _context(request: Request) -> AccessContext:
    if not isinstance(request.auth, AccessContext):  # guaranteed by SessionJWTAuthentication
        raise exceptions.NotAuthenticated()
    return request.auth


def _user_agent(request: Request) -> str:
    return str(request.META.get("HTTP_USER_AGENT", ""))


class PublicAuthView(AemsAPIView):
    """Public auth endpoint: no authentication classes, but still a Bearer challenge on 401."""

    permission_classes = [PublicEndpoint]
    authentication_classes = []

    def get_authenticate_header(self, request: Request) -> str:
        return WWW_AUTHENTICATE


class CsrfView(PublicAuthView):
    @extend_schema(
        operation_id="auth_csrf",
        summary="Issue the CSRF cookie",
        description=(
            "Sets the `csrftoken` cookie used as `X-CSRFToken` on cookie-authenticated calls."
        ),
        responses={200: s.CsrfResponseSerializer},
        tags=[TAG],
    )
    def get(self, request: Request) -> Response:
        get_token(request._request)  # CsrfViewMiddleware sets the cookie on the response
        return Response({"detail": "CSRF cookie set."})


class LoginView(PublicAuthView):
    @extend_schema(
        operation_id="auth_login",
        summary="Sign in",
        description=(
            "Returns a short-lived access token and sets the HttpOnly refresh-token cookie. "
            "Unknown "
            "accounts, wrong passwords and inactive accounts all return the same 401."
        ),
        request=s.LoginSerializer,
        responses={200: s.LoginResponseSerializer},
        extensions={PROBLEM_401_EXTENSION: True},
        tags=[TAG],
    )
    def post(self, request: Request) -> Response:
        serializer = s.LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = services.login(
            request=request._request,
            email=serializer.validated_data["email"],
            password=serializer.validated_data["password"],
            client_ip=client_ip(request),
            user_agent=_user_agent(request),
        )
        body = {**_token_body(result.tokens), "user": s.UserSerializer(result.user).data}
        response = Response(body)
        set_refresh_cookie(response, result.tokens.refresh_token, result.tokens.refresh_expires_at)
        return response


class RefreshView(PublicAuthView):
    @extend_schema(
        operation_id="auth_token_refresh",
        summary="Rotate the refresh token",
        description=(
            "Cookie-authenticated (CSRF required). Returns a new access token and rotates the "
            "refresh "
            "cookie. Reusing an already-rotated refresh token revokes the whole session."
        ),
        request=None,
        parameters=[REFRESH_COOKIE_PARAMETER, CSRF_HEADER_PARAMETER],
        responses={200: s.TokenResponseSerializer},
        extensions={PROBLEM_401_EXTENSION: True},
        tags=[TAG],
    )
    def post(self, request: Request) -> Response:
        enforce_csrf(request)
        ip = client_ip(request)
        services.check_refresh_rate_limit(ip)
        result = rotate(refresh_cookie_value(request), client_ip=ip)
        if result.outcome is not RotationOutcome.ROTATED or result.tokens is None:
            # Revocation (on reuse) has already committed; respond with a generic 401.
            raise _RefreshRejectedError()
        response = Response(_token_body(result.tokens))
        set_refresh_cookie(response, result.tokens.refresh_token, result.tokens.refresh_expires_at)
        return response

    def handle_exception(self, exc: Exception) -> Response:
        response = super().handle_exception(exc)
        if isinstance(exc, _RefreshRejectedError):
            clear_refresh_cookie(response)
        return response


class _RefreshRejectedError(exceptions.AuthenticationFailed):
    pass


def _lenient_bearer_session_id(request: Request) -> str | None:
    """Session id from a still-valid bearer token; logout must not fail on an expired one."""
    header = get_authorization_header(request).split()
    if len(header) != 2 or header[0].lower() != b"bearer":  # noqa: PLR2004
        return None
    try:
        return str(authenticate_access_token(header[1].decode("ascii")).session.id)
    except (UnicodeDecodeError, InvalidTokenError):
        return None


class LogoutView(PublicAuthView):
    """Revokes the session identified by the refresh cookie (CSRF required) or the bearer token."""

    @extend_schema(
        operation_id="auth_logout",
        summary="Sign out",
        description=(
            "Revokes the current session (identified by the refresh cookie, with CSRF, or by the "
            "bearer token) and clears the refresh cookie. Always 204."
        ),
        request=None,
        parameters=[REFRESH_COOKIE_PARAMETER, CSRF_HEADER_PARAMETER],
        responses={204: None},
        tags=[TAG],
    )
    def post(self, request: Request) -> Response:
        ip = client_ip(request)
        raw_refresh = refresh_cookie_value(request)
        session_id: str | None = None
        if raw_refresh:
            enforce_csrf(request)
            try:
                session_id = decode_refresh_token(raw_refresh).session_id
            except InvalidTokenError:
                session_id = None
        if session_id is None:
            session_id = _lenient_bearer_session_id(request)
        if session_id is not None:
            session = AuthSession.objects.filter(id=session_id).first()
            if session is not None:
                revoke_session(session, RevokeReason.LOGOUT, client_ip=ip)
        record_security_event("auth.logout", outcome="success", session_id=session_id, client_ip=ip)
        response = Response(status=status.HTTP_204_NO_CONTENT)
        clear_refresh_cookie(response)
        return response


class MeView(AemsAPIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        operation_id="auth_me_retrieve",
        summary="Current user",
        responses={200: s.UserSerializer},
        tags=[TAG],
    )
    def get(self, request: Request) -> Response:
        return Response(s.UserSerializer(_user(request)).data)

    @extend_schema(
        operation_id="auth_me_update",
        summary="Update the current user's profile",
        request=s.ProfileUpdateSerializer,
        responses={200: s.UserSerializer},
        tags=[TAG],
    )
    def patch(self, request: Request) -> Response:
        serializer = s.ProfileUpdateSerializer(_user(request), data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(s.UserSerializer(_user(request)).data)


class PasswordChangeView(AemsAPIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        operation_id="auth_password_change",
        summary="Change password",
        description=(
            "Requires the current password. Revokes every session (all devices) and returns a "
            "fresh "
            "access token plus a new refresh cookie for the caller."
        ),
        request=s.PasswordChangeSerializer,
        responses={200: s.TokenResponseSerializer},
        tags=[TAG],
    )
    def post(self, request: Request) -> Response:
        serializer = s.PasswordChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        context = _context(request)
        tokens = services.change_password(
            user=context.user,
            current_session=context.session,
            current_password=serializer.validated_data["current_password"],
            new_password=serializer.validated_data["new_password"],
            client_ip=client_ip(request),
            user_agent=_user_agent(request),
        )
        response = Response(_token_body(tokens))
        set_refresh_cookie(response, tokens.refresh_token, tokens.refresh_expires_at)
        return response


# Acceptance is not a delivery guarantee: the wording must hold when the account does not exist and
# when sending fails (AEMS-010).
GENERIC_RESET_DETAIL = (
    "If an account exists for that email address, a password reset link will be sent to it. "
    "If no email arrives, check the address and try again later."
)


class PasswordResetRequestView(PublicAuthView):
    @extend_schema(
        operation_id="auth_password_reset_request",
        summary="Request a password reset email",
        description=(
            "Always returns 202 with the same body and headers, whether or not the account exists "
            "and whether or not the email could be sent. Acceptance does not guarantee delivery."
        ),
        request=s.PasswordResetRequestSerializer,
        responses={202: s.DetailSerializer},
        tags=[TAG],
    )
    def post(self, request: Request) -> Response:
        serializer = s.PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        services.request_password_reset(
            email=serializer.validated_data["email"], client_ip=client_ip(request)
        )
        return Response({"detail": GENERIC_RESET_DETAIL}, status=status.HTTP_202_ACCEPTED)


class PasswordResetConfirmView(PublicAuthView):
    @extend_schema(
        operation_id="auth_password_reset_confirm",
        summary="Set a new password with a reset token",
        description="Single-use, expiring token. Revokes every existing session on success.",
        request=s.PasswordResetConfirmSerializer,
        responses={204: None},
        tags=[TAG],
    )
    def post(self, request: Request) -> Response:
        serializer = s.PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        services.confirm_password_reset(
            uid=serializer.validated_data["uid"],
            token=serializer.validated_data["token"],
            new_password=serializer.validated_data["new_password"],
            client_ip=client_ip(request),
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class SessionListView(AemsGenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = s.AuthSessionSerializer
    filterset_fields: list[str] = []
    ordering_fields = ["created_at", "last_rotated_at"]
    ordering = ["-created_at"]

    def get_queryset(self) -> Any:
        return AuthSession.objects.filter(
            user=_user(self.request), revoked_at__isnull=True, expires_at__gt=timezone.now()
        )

    def get_serializer_context(self) -> dict[str, Any]:
        context = super().get_serializer_context()
        auth = self.request.auth
        context["current_session_id"] = auth.session.id if isinstance(auth, AccessContext) else None
        return context

    @extend_schema(
        operation_id="auth_sessions_list",
        summary="List the current user's active sessions",
        tags=[TAG],
    )
    def get(self, request: Request) -> Response:
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        serializer = self.get_serializer(page, many=True)
        return self.get_paginated_response(serializer.data)


class SessionDetailView(AemsAPIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        operation_id="auth_sessions_revoke",
        summary="Revoke one of the current user's sessions",
        responses={204: None},
        tags=[TAG],
    )
    def delete(self, request: Request, session_id: Any) -> Response:
        session = AuthSession.objects.filter(
            id=session_id, user=_user(request), revoked_at__isnull=True
        ).first()
        if session is None:
            raise exceptions.NotFound()
        revoke_session(session, RevokeReason.USER_REVOKED, client_ip=client_ip(request))
        return Response(status=status.HTTP_204_NO_CONTENT)


class RevokeOtherSessionsView(AemsAPIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        operation_id="auth_sessions_revoke_others",
        summary="Revoke all of the current user's other sessions",
        request=None,
        responses={200: s.RevokedCountSerializer},
        tags=[TAG],
    )
    def post(self, request: Request) -> Response:
        context = _context(request)
        with transaction.atomic():
            revoked = revoke_user_sessions(
                context.user,
                RevokeReason.OTHER_SESSIONS_REVOKED,
                except_session_id=context.session.id,
                client_ip=client_ip(request),
            )
        return Response({"revoked": revoked})
