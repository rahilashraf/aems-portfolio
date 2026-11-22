from django.urls import path

from . import views

app_name = "platform"

urlpatterns = [
    path("organizations/", views.PlatformOrganizationListView.as_view(), name="organizations"),
    path(
        "organizations/<uuid:organization_id>/",
        views.PlatformOrganizationDetailView.as_view(),
        name="organization-detail",
    ),
]
