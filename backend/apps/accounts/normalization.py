"""Email identity normalization (ADR-0008).

One function, used on every write and lookup: strip surrounding whitespace, apply Unicode NFKC
normalization, then lowercase the whole address. Uniqueness is additionally enforced by the
database (``UniqueConstraint(Lower("email"))``), so a code path that skipped normalization still
cannot create a case-variant duplicate.
"""

import unicodedata


def normalize_email(value: str | None) -> str:
    if value is None:
        return ""
    return unicodedata.normalize("NFKC", str(value)).strip().lower()
