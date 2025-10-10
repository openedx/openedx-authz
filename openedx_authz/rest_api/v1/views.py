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
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from openedx_authz import api
from openedx_authz.rest_api.data import RoleOperationError, RoleOperationStatus
from openedx_authz.rest_api.utils import (
    filter_users,
    get_user_by_username_or_email,
    get_user_map,
    sort_users,
    view_auth_classes,
)
from openedx_authz.rest_api.v1.paginators import AuthZAPIViewPagination
from openedx_authz.rest_api.v1.permissions import DynamicScopePermission
from openedx_authz.rest_api.v1.serializers import (
    AddUsersToRoleWithScopeSerializer,
    ListRolesWithNamespaceSerializer,
    ListRolesWithScopeResponseSerializer,
    ListUsersInRoleWithScopeSerializer,
    PermissionValidationResponseSerializer,
    PermissionValidationSerializer,
    RemoveUsersFromRoleWithScopeSerializer,
    UserRoleAssignmentSerializer,
)

logger = logging.getLogger(__name__)

User = get_user_model()


@view_auth_classes()
class PermissionValidationMeView(APIView):
    """
    API view for validating user permissions against authorization policies.

    This view enables authenticated users to verify their permissions for specific
    actions and scopes within the Open edX authorization system. It supports batch
    validation of multiple permissions in a single request.

    **Endpoints**

    POST: Validate one or more permissions for the authenticated user

    **Request Format**

    Expects a list of permission objects, each containing:

    - action: The action to validate (e.g., 'edit_library', 'delete_library_content')
    - scope: The authorization scope (e.g., 'lib:DemoX:CSPROB')

    **Response Format**

    Returns a list of validation results, each containing:

    - action: The requested action
    - scope: The requested scope
    - allowed: Boolean indicating if the user has the permission

    **Authentication and Permissions**

    Requires authenticated user.

    **Example Request**

    POST /api/authz/v1/permissions/validate/me

    .. code-block:: json

        [
            {"action": "edit_library", "scope": "lib:DemoX:CSPROB"},
            {"action": "delete_library_content", "scope": "lib:DemoX:CSPR2"}
        ]

    **Example Response**

    .. code-block:: json

        [
            {"action": "edit_library", "scope": "lib:DemoX:CSPROB", "allowed": true},
            {"action": "delete_library_content", "scope": "lib:DemoX:CSPR2", "allowed": false}
        ]
    """

    @apidocs.schema(
        body=PermissionValidationSerializer(help_text="The permissions to validate", many=True),
        responses={
            status.HTTP_200_OK: PermissionValidationResponseSerializer,
            status.HTTP_400_BAD_REQUEST: "The request data is invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated",
        },
    )
    def post(self, request: HttpRequest) -> Response:
        """Validate one or more permissions for the authenticated user."""
        serializer = PermissionValidationSerializer(data=request.data, many=True)
        serializer.is_valid(raise_exception=True)

        username = request.user.username

        response_data = []
        for perm in serializer.validated_data:
            try:
                action = perm["action"]
                scope = perm["scope"]
                allowed = api.is_user_allowed(username, action, scope)
                response_data.append(
                    {
                        "action": action,
                        "scope": scope,
                        "allowed": allowed,
                    }
                )
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error(f"Error validating permission for user {username}: {e}")
                return Response(
                    data={"message": "An error occurred while validating permissions"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        serializer = PermissionValidationResponseSerializer(response_data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


@view_auth_classes()
class RoleUserAPIView(APIView):
    """
    API view for managing user-role assignments within specific authorization scopes.

    This view provides comprehensive role management capabilities, allowing administrators
    to view, assign, and remove role assignments for users within a given scope. It supports
    bulk operations for adding and removing multiple users, along with filtering, searching,
    sorting, and pagination of results.

    **Endpoints**

    - GET: Retrieve all users with their role assignments in a scope
    - PUT: Assign multiple users to a specific role within a scope
    - DELETE: Remove multiple users from a specific role within a scope

    **Query Parameters (GET)**

    - scope (Required): The authorization scope to query (e.g., 'lib:DemoX:CSPROB')
    - search (Optional): Search term to filter users by username, email or full name
    - roles (Optional): Filter by specific role names
    - page (Optional): Page number for pagination
    - page_size (Optional): Number of items per page
    - sort_by (Optional): Field to sort by (e.g., 'username', 'email', 'full_name')
    - order (Optional): Sort order ('asc' or 'desc')

    **Request Format (PUT)**

    .. code-block:: json

        {
            "role": "library_admin",
            "scope": "lib:DemoX:CSPROB",
            "users": ["user1@example.com", "username2"]
        }

    **Request Format (DELETE)**

    Query parameters:

    - users: Comma-separated list of user identifiers
    - role: The role to remove users from
    - scope: The scope to remove users from

    **Response Format (PUT/DELETE)**

    Returns HTTP 207 Multi-Status with:

    .. code-block:: json

        {
            "completed": [{"user_identifier": "john_doe", "status": "role_added"}],
            "errors": [{"user_identifier": "jane_doe", "error": "user_already_has_role"}]
        }

    **Authentication and Permissions**

    Requires authenticated user.
    Requires ``HasLibraryPermission``. Users must have appropriate permissions for the specified scope.

    **Notes**

    - User identifiers can be either username or email
    - Bulk operations return 207 Multi-Status to indicate partial success
    - Individual operation failures are reported in the errors array
    """

    pagination_class = AuthZAPIViewPagination
    permission_classes = [DynamicScopePermission]

    @apidocs.schema(
        parameters=[
            apidocs.query_parameter("scope", str, description="The authorization scope for the role"),
            apidocs.query_parameter("search", str, description="The search query to filter users by"),
            apidocs.query_parameter("roles", str, description="The names of the roles to query"),
            apidocs.query_parameter("page", int, description="Page number for pagination"),
            apidocs.query_parameter("page_size", int, description="Number of items per page"),
            apidocs.query_parameter("sort_by", str, description="The field to sort by"),
            apidocs.query_parameter("order", str, description="The order to sort by"),
        ],
        responses={
            status.HTTP_200_OK: "The users were retrieved successfully",
            status.HTTP_400_BAD_REQUEST: "The request parameters are invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated",
        },
    )
    def get(self, request: HttpRequest) -> Response:
        """Retrieve all users with role assignments within a specific scope."""
        serializer = ListUsersInRoleWithScopeSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        query_params = serializer.validated_data

        user_role_assignments = api.get_all_user_role_assignments_in_scope(query_params["scope"])
        usernames = {assignment.subject.username for assignment in user_role_assignments}
        response_data = UserRoleAssignmentSerializer(
            user_role_assignments, many=True, context={"user_map": get_user_map(usernames)}
        ).data

        filtered_users = filter_users(response_data, query_params["search"], query_params["roles"])
        user_role_assignments = sort_users(filtered_users, query_params["sort_by"], query_params["order"])

        paginator = self.pagination_class()
        paginated_response_data = paginator.paginate_queryset(user_role_assignments, request)
        return paginator.get_paginated_response(paginated_response_data)

    @apidocs.schema(
        body=AddUsersToRoleWithScopeSerializer,
        responses={
            status.HTTP_207_MULTI_STATUS: "The users were added to the role",
            status.HTTP_400_BAD_REQUEST: "The request data is invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated",
        },
    )
    def put(self, request: HttpRequest) -> Response:
        """Assign multiple users to a specific role within a scope."""
        serializer = AddUsersToRoleWithScopeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        role_name = serializer.validated_data["role"]
        scope = serializer.validated_data["scope"]

        completed, errors = [], []
        for user_identifier in serializer.validated_data["users"]:
            response_dict = {"user_identifier": user_identifier}
            try:
                user = get_user_by_username_or_email(user_identifier)
                result = api.assign_role_to_user_in_scope(user.username, role_name, scope)
                if result:
                    response_dict["status"] = RoleOperationStatus.ROLE_ADDED
                    completed.append(response_dict)
                else:
                    response_dict["error"] = RoleOperationError.USER_ALREADY_HAS_ROLE
                    errors.append(response_dict)
            except User.DoesNotExist:
                response_dict["error"] = RoleOperationError.USER_NOT_FOUND
                errors.append(response_dict)
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error(f"Error assigning role to user {user_identifier}: {e}")
                response_dict["error"] = RoleOperationError.ROLE_ASSIGNMENT_ERROR
                errors.append(response_dict)

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
        serializer = RemoveUsersFromRoleWithScopeSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)

        user_identifiers = serializer.validated_data["users"]
        role_name = serializer.validated_data["role"]
        scope = serializer.validated_data["scope"]

        completed, errors = [], []
        for user_identifier in user_identifiers:
            response_dict = {"user_identifier": user_identifier}
            try:
                user = get_user_by_username_or_email(user_identifier)
                result = api.unassign_role_from_user(user.username, role_name, scope)
                if result:
                    response_dict["status"] = RoleOperationStatus.ROLE_REMOVED
                    completed.append(response_dict)
                else:
                    response_dict["error"] = RoleOperationError.USER_DOES_NOT_HAVE_ROLE
                    errors.append(response_dict)
            except User.DoesNotExist:
                response_dict["error"] = RoleOperationError.USER_NOT_FOUND
                errors.append(response_dict)
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error(f"Error removing role from user {user_identifier}: {e}")
                response_dict["error"] = RoleOperationError.ROLE_REMOVAL_ERROR
                errors.append(response_dict)

        response_data = {"completed": completed, "errors": errors}
        return Response(response_data, status=status.HTTP_207_MULTI_STATUS)


@view_auth_classes()
class RoleListView(APIView):
    """API view for retrieving role definitions and their associated permissions within a specific namespace.

    This view provides read-only access to role definitions within a specific
    authorization namespace. It returns detailed information about each role including
    the permissions granted and the number of users assigned to each role.

    **Endpoints**

    GET: Retrieve all roles and their permissions for a specific namespace

    **Query Parameters**

    - namespace (Required): The namespace to query roles for (e.g., 'lib')
    - page (Optional): Page number for pagination
    - page_size (Optional): Number of items per page

    **Response Format**

    Returns a paginated list of role objects, each containing:

    - role: The role's external identifier (e.g., 'library_author', 'library_user')
    - permissions: List of permission action keys granted by this role
    - user_count: Number of users currently assigned to this role

    **Authentication and Permissions**

    Requires authenticated user.

    **Example Request**

    GET /api/authz/v1/roles/?namespace=lib&page=1&page_size=10

    **Example Response**

    .. code-block:: json

        {
            "count": 2,
            "next": null,
            "previous": null,
            "results": [
                {
                    "role": "library_author",
                    "permissions": ["delete_library_content", "edit_library"],
                    "user_count": 5
                },
                {
                    "role": "library_user",
                    "permissions": ["view_library", "view_library_team", "reuse_library_content"],
                    "user_count": 12
                }
            ]
        }
    """

    pagination_class = AuthZAPIViewPagination
    permission_classes = [IsAdminUser]

    @apidocs.schema(
        parameters=[
            apidocs.query_parameter("namespace", str, description="The namespace to query roles for"),
            apidocs.query_parameter("page", int, description="Page number for pagination"),
            apidocs.query_parameter("page_size", int, description="Number of items per page"),
        ],
        responses={
            status.HTTP_200_OK: ListRolesWithScopeResponseSerializer(many=True),
            status.HTTP_400_BAD_REQUEST: "The request parameters are invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated",
        },
    )
    def get(self, request: HttpRequest) -> Response:
        """Retrieve all roles and their permissions for a specific namespace."""
        serializer = ListRolesWithNamespaceSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)

        roles = api.get_role_definitions_in_scope(serializer.validated_data["namespace"])
        response_data = []
        for role in roles:
            users = api.get_users_for_role(role.external_key)
            response_data.append(
                {
                    "role": role.external_key,
                    "permissions": role.get_permission_identifiers(),
                    "user_count": len(users),
                }
            )

        serializer = ListRolesWithScopeResponseSerializer(response_data, many=True)

        paginator = self.pagination_class()
        paginated_response_data = paginator.paginate_queryset(response_data, request)
        return paginator.get_paginated_response(paginated_response_data)
