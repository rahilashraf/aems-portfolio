from django.urls import path

from . import invitation_views, views

app_name = "platform"

urlpatterns = [
    path("organizations/", views.PlatformOrganizationListView.as_view(), name="organizations"),
    path(
        "organizations/<uuid:organization_id>/",
        views.PlatformOrganizationDetailView.as_view(),
        name="organization-detail",
    ),
    path(
        "organizations/<uuid:organization_id>/initial-owner-invitation/",
        invitation_views.PlatformInitialOwnerInvitationView.as_view(),
        name="initial-owner-invitation",
    ),
    path(
        "organizations/<uuid:organization_id>/initial-owner-invitation/revoke/",
        invitation_views.PlatformInitialOwnerInvitationRevokeView.as_view(),
        name="initial-owner-invitation-revoke",
    ),
]
