from django.urls import path

from . import views

app_name = "auth"

urlpatterns = [
    path("csrf/", views.CsrfView.as_view(), name="csrf"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("token/refresh/", views.RefreshView.as_view(), name="token-refresh"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("me/", views.MeView.as_view(), name="me"),
    path("password/change/", views.PasswordChangeView.as_view(), name="password-change"),
    path("password/reset/", views.PasswordResetRequestView.as_view(), name="password-reset"),
    path(
        "password/reset/confirm/",
        views.PasswordResetConfirmView.as_view(),
        name="password-reset-confirm",
    ),
    path("sessions/", views.SessionListView.as_view(), name="sessions"),
    path(
        "sessions/revoke-others/",
        views.RevokeOtherSessionsView.as_view(),
        name="sessions-revoke-others",
    ),
    path("sessions/<uuid:session_id>/", views.SessionDetailView.as_view(), name="session-detail"),
]
