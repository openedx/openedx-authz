"""Open edX AuthZ API URLs."""

from django.urls import include, path

from openedx_authz.rest_api.v1 import urls as v1_urls

urlpatterns = [
    path("v1/", include(v1_urls)),
]
