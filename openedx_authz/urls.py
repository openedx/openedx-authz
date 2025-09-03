"""
URLs for openedx_authz.
"""

from django.urls import re_path, include
from rest_framework.routers import DefaultRouter
from .views import LibraryViewSet

router = DefaultRouter()
router.register(r"libraries", LibraryViewSet, basename="library")

urlpatterns = [
    re_path(r"^api/", include(router.urls)),
]
