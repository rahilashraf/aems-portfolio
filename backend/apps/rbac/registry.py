"""Code-defined permission catalog (ADR-0005, ADR-0017).

Each application registers the organization permissions its code checks, from its
``AppConfig.ready()``::

    registry.register("audit.view", "View the organization's audit history.", category="audit")

The registry is the source of truth at runtime:

- **Known codes only.** Evaluation ignores any code that is not registered (or is deprecated), so
  a stale database row or a typo in a view declaration can never grant access.
- **Conflicts are errors.** Registering the same code twice with a different definition raises
  :class:`PermissionRegistrationError` at startup. Re-registering an identical definition is a
  no-op (``ready()`` may run more than once in tests).
- **Codes are immutable.** A code is ``<category>.<action>`` in lower case. Renaming means
  deprecating the old code and registering a new one; the database keeps every code ever synced.

:func:`sync_permissions` (run after every ``migrate``) upserts the catalog into
``rbac.Permission``. It never deletes rows: a code no longer registered is marked deprecated, so
role history and audit records that name it stay meaningful. Deprecated permissions grant nothing
and cannot be added to roles.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from django.core.exceptions import ImproperlyConfigured

CODE_PATTERN = r"^[a-z][a-z_]*\.[a-z][a-z_]*$"
_CODE_RE = re.compile(CODE_PATTERN)
MAX_DESCRIPTION = 255


class PermissionRegistrationError(ImproperlyConfigured):
    """An invalid or conflicting permission definition."""


@dataclass(frozen=True)
class PermissionDefinition:
    code: str
    description: str
    category: str
    deprecated: bool = False


class PermissionRegistry:
    def __init__(self) -> None:
        self._definitions: dict[str, PermissionDefinition] = {}

    def register(
        self, code: str, description: str, *, category: str, deprecated: bool = False
    ) -> PermissionDefinition:
        if not _CODE_RE.fullmatch(code):
            msg = f"Invalid permission code {code!r}: expected '<category>.<action>'."
            raise PermissionRegistrationError(msg)
        if not description or len(description) > MAX_DESCRIPTION:
            msg = f"Permission {code!r} needs a description of at most {MAX_DESCRIPTION} chars."
            raise PermissionRegistrationError(msg)
        if not re.fullmatch(r"[a-z][a-z_]*", category):
            msg = f"Invalid category {category!r} for permission {code!r}."
            raise PermissionRegistrationError(msg)
        definition = PermissionDefinition(code, description, category, deprecated)
        existing = self._definitions.get(code)
        if existing is not None and existing != definition:
            msg = f"Permission {code!r} is already registered with a different definition."
            raise PermissionRegistrationError(msg)
        self._definitions[code] = definition
        return definition

    def definitions(self) -> list[PermissionDefinition]:
        return sorted(self._definitions.values(), key=lambda d: d.code)

    def get(self, code: str) -> PermissionDefinition | None:
        return self._definitions.get(code)

    def is_active(self, code: str) -> bool:
        """Registered and not deprecated: the only codes that can be held or granted."""
        definition = self._definitions.get(code)
        return definition is not None and not definition.deprecated

    def active_codes(self) -> frozenset[str]:
        return frozenset(c for c, d in self._definitions.items() if not d.deprecated)

    def unknown_or_inactive(self, codes: Iterable[str]) -> list[str]:
        return sorted({code for code in codes if not self.is_active(code)})


registry = PermissionRegistry()


def sync_permissions(using: str = "default") -> dict[str, int]:
    """Upsert the registry into ``rbac.Permission``. Idempotent; never deletes rows.

    Role-permission links are untouched, so existing assignments survive. A database code that is
    no longer registered is marked deprecated (it then grants nothing).
    """
    from .models import Permission  # noqa: PLC0415 - models are not ready at import time

    created = updated = deprecated = 0
    definitions = {d.code: d for d in registry.definitions()}
    existing = {p.code: p for p in Permission.objects.using(using).all()}
    for code, definition in definitions.items():
        row = existing.get(code)
        values: dict[str, Any] = {
            "description": definition.description,
            "category": definition.category,
            "is_deprecated": definition.deprecated,
        }
        if row is None:
            Permission.objects.using(using).create(code=code, **values)
            created += 1
        elif any(getattr(row, field) != value for field, value in values.items()):
            Permission.objects.using(using).filter(pk=row.pk).update(**values)
            updated += 1
    for code, row in existing.items():
        if code not in definitions and not row.is_deprecated:
            Permission.objects.using(using).filter(pk=row.pk).update(is_deprecated=True)
            deprecated += 1
    return {"created": created, "updated": updated, "deprecated": deprecated}


def sync_permissions_after_migrate(*, using: str = "default", **_: Any) -> None:
    sync_permissions(using)
