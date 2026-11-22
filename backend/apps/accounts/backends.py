"""Authentication backend: normalized-email lookup on top of Django's ModelBackend.

ModelBackend already runs the password hasher for unknown users (comparable timing) and rejects
inactive users after checking the password, so unknown, wrong-password and inactive cases are
indistinguishable to callers.
"""

from typing import Any

from django.contrib.auth.backends import ModelBackend
from django.http import HttpRequest

from .normalization import normalize_email


class EmailBackend(ModelBackend):
    def authenticate(
        self,
        request: HttpRequest | None,
        username: str | None = None,
        password: str | None = None,
        **kwargs: Any,
    ) -> Any:
        email = kwargs.pop("email", None) or username
        if email is None or password is None:
            return None
        return super().authenticate(request, username=normalize_email(email), password=password)
