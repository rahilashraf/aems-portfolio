"""URLconf with a duplicated, allowlisted URL name: both routes must be refused at runtime."""

from django.urls import path

from . import views

urlpatterns = [
    path("test-api/echo/", views.EchoView.as_view(), name="test-echo"),
    path("test-api/echo-shadow/", views.UnlistedPublicEndpointView.as_view(), name="test-echo"),
]

handler404 = "apps.core.errors.page_not_found"
handler500 = "apps.core.errors.server_error"
