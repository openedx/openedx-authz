"""
REST API views for Open edX Authorization (AuthZ) system.

This module provides Django REST Framework views for managing authorization
permissions, roles, and user assignments within Open edX platform.
"""

import logging

import edx_api_doc_tools as apidocs
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from openedx_authz.api.data import ContentLibraryData
from openedx_authz.api.roles import (
    get_all_roles_and_subjects_in_scope,
    get_role_definitions_in_scope,
    get_all_users_by_role,
)
from openedx_authz.api.users import (
    assign_role_to_user_in_scope,
    get_user_role_assignments_for_role_in_scope,
    unassign_role_from_user,
    user_has_permission,
    get_all_user_role_assignments_in_scope,
)
from openedx_authz.rest_api.v1.serializers import (
    AddUserToRoleWithScopeSerializer,
    ListRolesWithScopeResponseSerializer,
    ListRolesWithScopeSerializer,
    ListUsersInRoleWithScopeResponseSerializer,
    ListUsersInRoleWithScopeSerializer,
    PermissionValidationResponseSerializer,
    PermissionValidationSerializer,
    RemoveUserFromRoleWithScopeSerializer,
)

try:
    from common.djangoapps.student.models.user import get_user_by_username_or_email
except ImportError:
    get_user_by_username_or_email = None

logger = logging.getLogger(__name__)

User = get_user_model()


class PermissionValidationView(APIView):
    """
    API view for validating user permissions against authorization policies.

    This view allows authenticated users to check whether they have
    specific permissions for given actions and scopes within the system.
    Supports batch permission validation through POST request.
    """

    permission_classes = [IsAuthenticated]

    @apidocs.schema(
        body=PermissionValidationSerializer(help_text="The permissions to validate", many=True),
        responses={
            status.HTTP_200_OK: PermissionValidationResponseSerializer,
            status.HTTP_400_BAD_REQUEST: "The request data is invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated",
        },
    )
    def post(self, request: HttpRequest) -> Response:
        """Validate permissions for the authenticated user."""
        serializer = PermissionValidationSerializer(data=request.data, many=True)
        serializer.is_valid(raise_exception=True)

        username = request.user.username

        response_data = []
        for perm in serializer.validated_data:
            try:
                action = perm["action"]
                scope = perm["scope"]
                allowed = user_has_permission(username, action, scope)
                response_data.append(
                    {
                        "action": action,
                        "scope": scope,
                        "allowed": allowed,
                    }
                )
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error(f"Error validating permission for user {username}: {e}")

        serializer = PermissionValidationResponseSerializer(response_data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class RoleUserAPIView(APIView):
    """
    API view for managing user-role assignments within specific scope.
    """

    permission_classes = [IsAuthenticated]

    @apidocs.schema(
        parameters=[
            apidocs.query_parameter("role", str, description="The name of the role to query"),
            apidocs.query_parameter("scope", str, description="The authorization scope for the role"),
        ],
        responses={
            status.HTTP_200_OK: ListUsersInRoleWithScopeResponseSerializer(many=True),
            status.HTTP_400_BAD_REQUEST: "The request parameters are invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated",
        },
    )
    def get(self, request: HttpRequest) -> Response:
        """Retrieve all users assigned to a specific role within a scope."""
        serializer = ListUsersInRoleWithScopeSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)

        role_name = serializer.validated_data.get("role")
        scope = serializer.validated_data["scope"]

        response_data = []

        scope_data = ContentLibraryData(external_key=scope)

        # TODO: Should this be another endpoint?
        if not role_name:
            roles = get_all_roles_and_subjects_in_scope(scope_data)
            return Response(roles, status=status.HTTP_200_OK)

        role_assignments = get_user_role_assignments_for_role_in_scope(role_name, scope)
        for assignment in role_assignments:
            # TODO: Should we get all users at once instead of one by one?
            user = get_user_by_username_or_email(assignment.subject.username)
            response_data.append(
                {
                    "username": assignment.subject.username,
                    "full_name": user.profile.name,
                    "email": user.email,
                }
            )

        serializer = ListUsersInRoleWithScopeResponseSerializer(response_data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @apidocs.schema(
        body=AddUserToRoleWithScopeSerializer,
        responses={
            status.HTTP_207_MULTI_STATUS: "The users were added to the role",
            status.HTTP_400_BAD_REQUEST: "The request data is invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated",
        },
    )
    def put(self, request: HttpRequest) -> Response:
        """Assign multiple users to a specific role within a scope."""
        serializer = AddUserToRoleWithScopeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        completed, errors = [], []
        role_name = serializer.validated_data["role"]
        scope = serializer.validated_data["scope"]

        for user_identifier in serializer.validated_data["users"]:
            try:
                user = get_user_by_username_or_email(user_identifier)
                assign_role_to_user_in_scope(user.username, role_name, scope)
                completed.append({"user": user_identifier, "status": "role_added"})
            except User.DoesNotExist:
                errors.append({"user": user_identifier, "error": "user_not_found"})
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error(f"Error assigning role to user {user_identifier}: {e}")
                errors.append({"user": user_identifier, "error": "assignment_failed"})

        response_data = {"completed": completed, "errors": errors}
        return Response(response_data, status=status.HTTP_207_MULTI_STATUS)

    @apidocs.schema(
        parameters=[
            apidocs.query_parameter("user", str, description="The user to remove from the role"),
            apidocs.query_parameter("role", str, description="The role to remove the user from"),
            apidocs.query_parameter("scope", str, description="The scope to remove the user from"),
        ],
        responses={
            status.HTTP_200_OK: "The user was removed from the role",
            status.HTTP_400_BAD_REQUEST: "The request data is invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated",
            status.HTTP_404_NOT_FOUND: "The user was not found",
            status.HTTP_500_INTERNAL_SERVER_ERROR: "The user was not removed from the role",
        },
    )
    def delete(self, request: HttpRequest) -> Response:
        """Remove a user from a specific role within a scope."""
        serializer = RemoveUserFromRoleWithScopeSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)

        # Should we allow a list of users separated by a comma?
        user_identifier = serializer.validated_data["user"]
        role_name = serializer.validated_data["role"]
        scope = serializer.validated_data["scope"]

        try:
            user = get_user_by_username_or_email(user_identifier)
            unassign_role_from_user(user.username, role_name, scope)
            return Response({"message": "Role successfully removed from user"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error(f"Error removing role from user {user_identifier}: {e}")
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RoleListView(APIView):
    """
    API view for retrieving role definitions and their associated permissions.
    """

    permission_classes = [IsAuthenticated]

    @apidocs.schema(
        parameters=[
            apidocs.query_parameter("scope", str, description="The scope to query roles for"),
        ],
        responses={
            status.HTTP_200_OK: ListRolesWithScopeResponseSerializer(many=True),
            status.HTTP_400_BAD_REQUEST: "The request parameters are invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated",
        },
    )
    def get(self, request: HttpRequest) -> Response:
        """Retrieve all roles and their permissions for a specific scope."""
        serializer = ListRolesWithScopeSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)

        scope = ContentLibraryData(namespaced_key=serializer.validated_data["scope"])

        response_data = []
        roles = get_role_definitions_in_scope(scope)

        for role in roles:
            users = get_all_users_by_role(role)
            permissions = [perm.action.external_key for perm in role.permissions] if role.permissions else []
            response_data.append(
                {
                    "role": role.external_key,
                    "permissions": permissions,
                    "user_count": len(users),
                }
            )

        serializer = ListRolesWithScopeResponseSerializer(response_data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
