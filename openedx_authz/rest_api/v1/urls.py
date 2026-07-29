"""Open edX AuthZ API v1 URLs."""

from django.urls import path

from openedx_authz.rest_api.v1 import views
from openedx_authz.rest_api.v1.admin_console import views as admin_console_views
from openedx_authz.rest_api.v1.course_authoring import views as course_authoring_views

urlpatterns = [
    path(
        "permissions/validate/me",
        views.PermissionValidationMeView.as_view(),
        name="permission-validation-me",
    ),
    path("roles/", views.RoleListView.as_view(), name="role-list"),
    path("roles/users/", views.RoleUserAPIView.as_view(), name="role-user-list"),
    path("orgs/", admin_console_views.AdminConsoleOrgsAPIView.as_view(), name="orgs-list"),
    path("users/", admin_console_views.TeamMembersAPIView.as_view(), name="user-list"),
    path("users/validate/", views.UserValidationAPIView.as_view(), name="user-validation"),
    path(
        "users/<str:username>/assignments/",
        admin_console_views.TeamMemberAssignmentsAPIView.as_view(),
        name="user-assignment-list",
    ),
    path("assignments/", admin_console_views.AssignmentsAPIView.as_view(), name="assignment-list"),
    path("scopes/", admin_console_views.ScopesAPIView.as_view(), name="scope-list"),
    path(
        "waffle-flag-states/",
        course_authoring_views.WaffleFlagStatesAPIView.as_view(),
        name="waffle-flag-states",
    ),
]
