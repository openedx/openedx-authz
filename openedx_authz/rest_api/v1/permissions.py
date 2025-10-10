"""Permissions for the Open edX AuthZ REST API."""

from rest_framework.permissions import SAFE_METHODS, BasePermission

from openedx_authz import api


class HasLibraryPermission(BasePermission):
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
        user = request.user

        if user.is_superuser or user.is_staff:
            return True

        scope = request.data.get("scope") if request.data else request.query_params.get("scope")

        if not scope:
            return False

        if request.method in SAFE_METHODS:
            return api.is_user_allowed(user.username, "view_library_team", scope)
        return api.is_user_allowed(user.username, "manage_library_team", scope)
