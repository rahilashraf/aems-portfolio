from django.urls import path

from . import views

app_name = "platform-audit"

urlpatterns = [
    path("audit-logs/", views.PlatformAuditLogListView.as_view(), name="audit-logs"),
]
