from django.db import models

from apps.core.models import BaseModel


class Widget(BaseModel):
    """Concrete model built on the shared abstract base (UUIDv4 PK + timestamps)."""

    name = models.CharField(max_length=100)
    category = models.CharField(max_length=50)
    quantity = models.PositiveIntegerField(default=0)

    class Meta:
        app_label = "fixtures_app"

    def __str__(self) -> str:
        return self.name
