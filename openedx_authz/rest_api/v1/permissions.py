"""Permissions for the Open edX AuthZ REST API."""

# from rest_framework import serializers
from rest_framework.permissions import SAFE_METHODS, BasePermission

from openedx_authz import api

RESOURCE_PERMISSIONS = {
    "lib": {
        "view": "view_library_team",
        "manage": "manage_library_team",
    },
    "course": {
        "view": "view_course_team",
        "manage": "manage_course_team",
    },
}


class HasScopedPermission(BasePermission):
    """Permission to check if the user has the library permission."""

    def has_permission(self, request, view):
        """
        Check if the user has the appropriate library permission based on the request method.

        For safe methods (GET, HEAD, OPTIONS), checks for 'view_library_team' permission.
        For unsafe methods (POST, PUT, PATCH, DELETE), checks for 'manage_library_team' permission.

        Returns:
            bool: True if user has the required permission for the scope, False otherwise

        Note:
            Requires a 'scope' parameter in either request.data or query_params.
            Returns False if no scope is provided.
        """
        scope_value = request.data.get("scope") if request.data else request.query_params.get("scope")
        if not scope_value:
            return False

        try:
            scope = api.ScopeData(external_key=scope_value)
        except ValueError:
            return False

        resource_type = scope.NAMESPACE
        perms = RESOURCE_PERMISSIONS.get(resource_type)

        if not perms:
            return False

        user = request.user
        if user.is_superuser or user.is_staff:
            return True

        perm_name = perms["view"] if request.method in SAFE_METHODS else perms["manage"]
        return api.is_user_allowed(user.username, perm_name, scope)
