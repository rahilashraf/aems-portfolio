"""OpenAPI extensions for accounts authentication."""

from typing import Any

from drf_spectacular.extensions import OpenApiAuthenticationExtension


class SessionJWTAuthenticationScheme(OpenApiAuthenticationExtension):  # type: ignore[no-untyped-call]
    target_class = "apps.accounts.authentication.SessionJWTAuthentication"
    name = "bearerAuth"

    def get_security_definition(self, auto_schema: Any) -> dict[str, Any]:
        return {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": (
                "Short-lived access token from /api/v1/auth/login/ or /api/v1/auth/token/refresh/. "
                "Validated against the server-side session on every request."
            ),
        }
