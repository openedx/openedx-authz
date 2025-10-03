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
from openedx_authz.api.roles import get_all_users_by_role, get_role_definitions_in_scope
from openedx_authz.api.users import (
    assign_role_to_user_in_scope,
    get_all_user_role_assignments_in_scope_v2,
    unassign_role_from_user,
    user_has_permission,
)
from openedx_authz.rest_api.utils import get_user_by_username_or_email
from openedx_authz.rest_api.v1.paginators import AuthZAPIViewPagination
from openedx_authz.rest_api.v1.serializers import (
    AddUserToRoleWithScopeSerializer,
    ListRolesWithScopeResponseSerializer,
    ListRolesWithScopeSerializer,
    ListUsersInRoleWithScopeSerializer,
    PermissionValidationResponseSerializer,
    PermissionValidationSerializer,
    RemoveUserFromRoleWithScopeSerializer,
    RoleAssignmentSerializer,
)

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
    pagination_class = AuthZAPIViewPagination

    @apidocs.schema(
        parameters=[
            apidocs.query_parameter("role", str, description="The name of the role to query"),
            apidocs.query_parameter("scope", str, description="The authorization scope for the role"),
            apidocs.query_parameter("page", int, description="Page number for pagination"),
            apidocs.query_parameter("page_size", int, description="Number of items per page"),
        ],
        responses={
            status.HTTP_200_OK: "The users were retrieved successfully",
            status.HTTP_400_BAD_REQUEST: "The request parameters are invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated",
        },
    )
    def get(self, request: HttpRequest) -> Response:
        """Retrieve all users with role assignments within a specific scope."""
        # TODO: Filter by role
        serializer = ListUsersInRoleWithScopeSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        user_role_assignments = get_all_user_role_assignments_in_scope_v2(serializer.validated_data["scope"])

        paginator = self.pagination_class()
        paginated_assignments = paginator.paginate_queryset(user_role_assignments, request)

        serializer = RoleAssignmentSerializer(paginated_assignments, many=True)
        return paginator.get_paginated_response(serializer.data)

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

        # TODO: Should we validate that the role or scope exists?
        role_name = serializer.validated_data["role"]
        scope = serializer.validated_data["scope"]

        completed, errors = [], []
        for user_identifier in serializer.validated_data["users"]:
            try:
                user = get_user_by_username_or_email(user_identifier)
                assign_role_to_user_in_scope(user.username, role_name, scope)
                completed.append({"user_identifier": user_identifier, "status": "role_added"})
            except User.DoesNotExist:
                errors.append({"user_identifier": user_identifier, "error": "user_not_found"})
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error(f"Error assigning role to user {user_identifier}: {e}")
                errors.append({"user_identifier": user_identifier, "error": "assignment_failed"})

        response_data = {"completed": completed, "errors": errors}
        return Response(response_data, status=status.HTTP_207_MULTI_STATUS)

    @apidocs.schema(
        parameters=[
            apidocs.query_parameter(
                "users", str, description="List of user identifiers (username or email) separated by a comma"
            ),
            apidocs.query_parameter("role", str, description="The role to remove the users from"),
            apidocs.query_parameter("scope", str, description="The scope to remove the users from"),
        ],
        responses={
            status.HTTP_207_MULTI_STATUS: "The users were removed from the role",
            status.HTTP_400_BAD_REQUEST: "The request parameters are invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated",
        },
    )
    def delete(self, request: HttpRequest) -> Response:
        """Remove multiple users from a specific role within a scope."""
        serializer = RemoveUserFromRoleWithScopeSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)

        user_identifiers = serializer.validated_data["users"]
        role_name = serializer.validated_data["role"]
        scope = serializer.validated_data["scope"]

        completed, errors = [], []
        for user_identifier in user_identifiers:
            try:
                user = get_user_by_username_or_email(user_identifier)
                unassign_role_from_user(user.username, role_name, scope)
                completed.append({"user_identifier": user_identifier, "status": "role_removed"})
            except User.DoesNotExist:
                errors.append({"user_identifier": user_identifier, "error": "user_not_found"})
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error(f"Error removing role from user {user_identifier}: {e}")
                errors.append({"user_identifier": user_identifier, "error": "removal_failed"})

        response_data = {"completed": completed, "errors": errors}
        return Response(response_data, status=status.HTTP_207_MULTI_STATUS)


class RoleListView(APIView):
    """
    API view for retrieving role definitions and their associated permissions.
    """

    permission_classes = [IsAuthenticated]
    pagination_class = AuthZAPIViewPagination

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
        roles = get_role_definitions_in_scope(scope)

        response_data = []
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

        paginator = self.pagination_class()
        paginated_response_data = paginator.paginate_queryset(response_data, request)

        serializer = ListRolesWithScopeResponseSerializer(paginated_response_data, many=True)
        return paginator.get_paginated_response(serializer.data)
