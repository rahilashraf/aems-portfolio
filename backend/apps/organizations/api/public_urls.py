"""Public, token-scoped invitation routes (allowlisted in ``API_PUBLIC_ENDPOINTS``; ADR-0018)."""

from django.urls import path

from . import invitation_views

app_name = "invitations"

urlpatterns = [
    path("<str:token>/", invitation_views.InvitationPreviewView.as_view(), name="preview"),
    path("<str:token>/accept/", invitation_views.InvitationAcceptView.as_view(), name="accept"),
]
