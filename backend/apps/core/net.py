"""Client network information.

The client IP is ``REMOTE_ADDR`` unless ``settings.TRUSTED_PROXY_COUNT`` is set to the exact
number of trusted reverse proxies in front of the application. Only then is ``X-Forwarded-For``
consulted, taking the address appended by the outermost trusted proxy (counting from the right).
Client-supplied forwarding headers are never trusted by default.
"""

import ipaddress
from typing import Any

from django.conf import settings


def _valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def client_ip(request: Any) -> str | None:
    meta = getattr(request, "META", {})
    trusted = int(getattr(settings, "TRUSTED_PROXY_COUNT", 0) or 0)
    if trusted > 0:
        forwarded = [part.strip() for part in str(meta.get("HTTP_X_FORWARDED_FOR", "")).split(",")]
        forwarded = [part for part in forwarded if part]
        if len(forwarded) >= trusted:
            candidate = _valid_ip(forwarded[-trusted])
            if candidate:
                return candidate
    return _valid_ip(str(meta.get("REMOTE_ADDR", "")))
