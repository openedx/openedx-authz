"""Open edX AuthZ API v1 URLs."""

from django.urls import path

from openedx_authz.rest_api.v1 import views

urlpatterns = [
    path(
        "permissions/validate/me",
        views.PermissionValidationMeView.as_view(),
        name="permission-validation-me",
    ),
    path("roles/", views.RoleListView.as_view(), name="role-list"),
    path("roles/users/", views.RoleUserAPIView.as_view(), name="role-user-list"),
    path("orgs/", views.AdminConsoleOrgsAPIView.as_view(), name="orgs-list"),
    path("users/", views.TeamMembersAPIView.as_view(), name="user-list"),
    path("users/validate/", views.UserValidationAPIView.as_view(), name="user-validation"),
    path(
        "users/<str:username>/assignments/", views.TeamMemberAssignmentsAPIView.as_view(), name="user-assignment-list"
    ),
    path("assignments/", views.AssignmentsAPIView.as_view(), name="assignment-list"),
    path("scopes/", views.ScopesAPIView.as_view(), name="scope-list"),
]
