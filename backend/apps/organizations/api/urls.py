from django.urls import path

from . import views

app_name = "organizations"

urlpatterns = [
    path("", views.MyOrganizationListView.as_view(), name="list"),
    path("<uuid:org_id>/", views.OrganizationDetailView.as_view(), name="detail"),
    path("<uuid:org_id>/me/", views.OrganizationMembershipView.as_view(), name="me"),
]
