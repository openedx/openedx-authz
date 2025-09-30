"""Open edX AuthZ API v1 URLs."""

from django.urls import path

from openedx_authz.rest_api.v1 import views

urlpatterns = [
    path("permissions/validate/me", views.PermissionValidationMeView.as_view(), name="permission-validation-me"),
    path("roles/", views.RoleListView.as_view(), name="role-list"),
    path("roles/users/", views.RoleUserAPIView.as_view(), name="role-user-list"),
]
