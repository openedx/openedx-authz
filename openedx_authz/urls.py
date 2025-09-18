"""
URLs for openedx_authz.
"""

from django.urls import include, re_path
from rest_framework.routers import DefaultRouter

from .views import AdminRoleAssignmentViewSet, LibraryViewSet, PolicyBulkViewSet, PolicySingleViewSet

router = DefaultRouter()
router.register(r"libraries", LibraryViewSet, basename="library")
router.register(r"admin-roles", AdminRoleAssignmentViewSet, basename="admin-roles")
router.register(r"policy-bulk", PolicyBulkViewSet, basename="policy-bulk")
router.register(r"policy-single", PolicySingleViewSet, basename="policy-single")

urlpatterns = [
    re_path(r"^api/", include(router.urls)),
]
