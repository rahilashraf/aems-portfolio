from django.urls import path

from apps.audit.api.views import OrganizationAuditLogListView
from apps.rbac.api import views as rbac_views

from . import invitation_views, views

app_name = "organizations"

urlpatterns = [
    path("", views.MyOrganizationListView.as_view(), name="list"),
    path("<uuid:org_id>/", views.OrganizationDetailView.as_view(), name="detail"),
    path("<uuid:org_id>/me/", views.OrganizationMembershipView.as_view(), name="me"),
    path("<uuid:org_id>/audit-logs/", OrganizationAuditLogListView.as_view(), name="audit-logs"),
    path("<uuid:org_id>/members/", rbac_views.MemberListView.as_view(), name="members"),
    path(
        "<uuid:org_id>/members/<uuid:membership_id>/",
        rbac_views.MemberDetailView.as_view(),
        name="member-detail",
    ),
    path(
        "<uuid:org_id>/members/<uuid:membership_id>/roles/",
        rbac_views.MemberRolesView.as_view(),
        name="member-roles",
    ),
    path("<uuid:org_id>/roles/", rbac_views.RoleListView.as_view(), name="roles"),
    path(
        "<uuid:org_id>/roles/<uuid:role_id>/",
        rbac_views.RoleDetailView.as_view(),
        name="role-detail",
    ),
    path("<uuid:org_id>/permissions/", rbac_views.PermissionListView.as_view(), name="permissions"),
    path(
        "<uuid:org_id>/invitations/",
        invitation_views.InvitationListView.as_view(),
        name="invitations",
    ),
    path(
        "<uuid:org_id>/invitations/<uuid:invitation_id>/revoke/",
        invitation_views.InvitationRevokeView.as_view(),
        name="invitation-revoke",
    ),
]
