"""Open edX AuthZ API v1 URLs."""

from django.urls import path

from openedx_authz.rest_api.v1 import views

urlpatterns = [
    path("permissions/validate/", views.PermissionValidationView.as_view(), name="permission-validate"),
    path("roles/", views.RoleListView.as_view(), name="role-list"),
    path("roles/users/", views.RoleUserAPIView.as_view(), name="roles-users"),
]
