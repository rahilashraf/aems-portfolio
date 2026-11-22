"""Additional password validators."""

from typing import Any

from django.core.exceptions import ValidationError


class MaximumLengthValidator:
    """Reject excessively long passwords (bounds hashing cost; prevents amplification DoS)."""

    def __init__(self, max_length: int = 128) -> None:
        self.max_length = max_length

    def validate(self, password: str, user: Any = None) -> None:
        if len(password) > self.max_length:
            raise ValidationError(
                f"This password is too long. It must contain at most {self.max_length} characters.",
                code="password_too_long",
                params={"max_length": self.max_length},
            )

    def get_help_text(self) -> str:
        return f"Your password must contain at most {self.max_length} characters."
