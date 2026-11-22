"""Refresh-token cookie handling. The refresh token is never placed in a response body."""

from datetime import datetime
from typing import Any

from django.conf import settings
from rest_framework.response import Response


def refresh_cookie_value(request: Any) -> str:
    return str(request.COOKIES.get(settings.AUTH_REFRESH_COOKIE["NAME"], "") or "")


def set_refresh_cookie(response: Response, token: str, expires_at: datetime) -> None:
    cfg = settings.AUTH_REFRESH_COOKIE
    response.set_cookie(
        cfg["NAME"],
        token,
        expires=expires_at,
        path=cfg["PATH"],
        secure=cfg["SECURE"],
        httponly=True,
        samesite=cfg["SAMESITE"],
        domain=cfg.get("DOMAIN"),
    )


def clear_refresh_cookie(response: Response) -> None:
    cfg = settings.AUTH_REFRESH_COOKIE
    response.delete_cookie(
        cfg["NAME"], path=cfg["PATH"], domain=cfg.get("DOMAIN"), samesite=cfg["SAMESITE"]
    )
