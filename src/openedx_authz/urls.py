"""Open edX AuthZ API URLs."""

from django.urls import include, path

from openedx_authz.rest_api import urls

app_name = "openedx_authz"

urlpatterns = [
    path("authz/", include((urls, "openedx_authz"))),
]
