from django.db import models

from apps.core.models import BaseModel
from apps.organizations.tenancy import TenantScopedModel


class Widget(BaseModel):
    """Concrete model built on the shared abstract base (UUIDv4 PK + timestamps)."""

    name = models.CharField(max_length=100)
    category = models.CharField(max_length=50)
    quantity = models.PositiveIntegerField(default=0)

    class Meta:
        app_label = "fixtures_app"

    def __str__(self) -> str:
        return self.name


class TenantNote(TenantScopedModel):
    """Test-only tenant resource for the isolation matrix (nested references, writes)."""

    title = models.CharField(max_length=100)
    # Must reference a note of the same organization (validated by the scoped serializer field).
    parent = models.ForeignKey("self", null=True, blank=True, on_delete=models.PROTECT)

    class Meta:
        app_label = "fixtures_app"

    def __str__(self) -> str:
        return self.title
