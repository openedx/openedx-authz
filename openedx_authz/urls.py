"""
URLs for openedx_authz.
"""

from django.urls import re_path, include
from rest_framework.routers import DefaultRouter
from .views import LibraryViewSet, AdminRoleAssignmentViewSet, UserPermissionViewSet

router = DefaultRouter()
router.register(r"libraries", LibraryViewSet, basename="library")
router.register(r"admin-roles", AdminRoleAssignmentViewSet, basename="admin-roles")
router.register(r"user-permissions", UserPermissionViewSet, basename="user-permissions")

urlpatterns = [
    re_path(r"^api/", include(router.urls)),
]
