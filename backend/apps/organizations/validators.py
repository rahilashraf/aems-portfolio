"""Normalization and validation for organization slugs and IANA timezones."""

import re
import zoneinfo
from functools import lru_cache

from django.core.exceptions import ValidationError

SLUG_MIN_LENGTH = 3
SLUG_MAX_LENGTH = 63
# Lowercase ASCII letters and digits in hyphen-separated groups: no leading, trailing or repeated
# hyphens. The same pattern is enforced by a database CHECK constraint.
SLUG_PATTERN = r"^[a-z0-9]+(-[a-z0-9]+)*$"
_SLUG_RE = re.compile(SLUG_PATTERN)

# Entries of the zone database that are not location identifiers.
_NON_LOCATION_ZONES = frozenset({"localtime", "posixrules", "Factory"})


def normalize_slug(value: str | None) -> str:
    return (value or "").strip().lower()


def validate_slug(value: str) -> None:
    if not SLUG_MIN_LENGTH <= len(value) <= SLUG_MAX_LENGTH:
        msg = f"Use between {SLUG_MIN_LENGTH} and {SLUG_MAX_LENGTH} characters."
        raise ValidationError(msg, code="invalid_slug")
    if not _SLUG_RE.fullmatch(value):
        msg = "Use lowercase letters, digits and single hyphens between them."
        raise ValidationError(msg, code="invalid_slug")


@lru_cache(maxsize=1)
def supported_timezones() -> frozenset[str]:
    """IANA identifiers available to this Python runtime (system tzdata or the tzdata package)."""
    return frozenset(zoneinfo.available_timezones()) - _NON_LOCATION_ZONES


def validate_timezone(value: str) -> None:
    if value not in supported_timezones():
        msg = "Use an IANA time zone identifier such as 'Europe/London' or 'UTC'."
        raise ValidationError(msg, code="invalid_timezone")
