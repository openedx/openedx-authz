"""
REST API views for Open edX Authorization (AuthZ) system.

This module provides Django REST Framework views for managing authorization
permissions, roles, and user assignments within Open edX platform.

These endpoints are generic to Authorization. Any consumer can call them as-is, with
no assumptions about which application is calling.
"""

import logging

import edx_api_doc_tools as apidocs
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from openedx_authz import api
from openedx_authz.api.utils import get_user_map
from openedx_authz.constants import permissions
from openedx_authz.filters import PermissionValidationRequested, RoleAssignmentRequested, RoleRemovalRequested
from openedx_authz.rest_api.data import RoleOperationError, RoleOperationStatus
from openedx_authz.rest_api.decorators import authz_permissions, view_auth_classes
from openedx_authz.rest_api.utils import filter_users, sort_users
from openedx_authz.rest_api.v1.paginators import AuthZAPIViewPagination
from openedx_authz.rest_api.v1.permissions import AnyScopePermission, DynamicScopePermission, ScopeTypePermission
from openedx_authz.rest_api.v1.serializers import (
    AddUsersToRoleWithScopeSerializer,
    ListRolesQuerySerializer,
    ListUsersInRoleWithScopeSerializer,
    PermissionValidationResponseSerializer,
    PermissionValidationSerializer,
    RemoveUsersFromRoleWithScopeSerializer,
    RoleCatalogMetaSerializer,
    RoleCatalogResponseSerializer,
    RoleCatalogRoleSerializer,
    UserRoleAssignmentSerializer,
    UserValidationAPIViewResponseSerializer,
    UserValidationAPIViewSerializer,
)
from openedx_authz.utils import get_user_by_username_or_email

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

    - POST: Validate one or more permissions for the authenticated user

    **Request Format**

    Expects a list of permission objects, each containing:

    - action: The action to validate (e.g., 'content_libraries.edit_library_content')
    - scope (Optional): The authorization scope (e.g., 'lib:DemoX:CSPROB'). When omitted,
      the permission is validated across any scope (the user is allowed if they have the
      permission in at least one scope).

    **Response Format**

    Returns a list of validation results, each containing:

    - action: The requested action
    - scope: The requested scope (only present when a scope was provided in the request)
    - allowed: Boolean indicating if the user has the permission

    **Authentication and Permissions**

    - Requires authenticated user.

    **Example Request**

    POST /api/authz/v1/permissions/validate/me::

        [
            {"action": "edit_library", "scope": "lib:DemoX:CSPROB"},
            {"action": "delete_library_content", "scope": "lib:OpenedX:CS50"}
        ]

    **Example Response**::

        [
            {"action": "edit_library", "scope": "lib:DemoX:CSPROB", "allowed": true},
            {"action": "delete_library_content", "scope": "lib:OpenedX:CS50", "allowed": false}
        ]

    **Example Request (without scope)**

    POST /api/authz/v1/permissions/validate/me::

        [
            {"action": "content_libraries.manage_library_team"},
            {"action": "courses.manage_course_team"}
        ]

    **Example Response (without scope)**::

        [
            {"action": "content_libraries.manage_library_team", "allowed": true},
            {"action": "courses.manage_course_team", "allowed": false}
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
        data = serializer.validated_data

        username = request.user.username
        response_data = []
        for permission in data:
            try:
                action = permission["action"]
                scope = permission.get("scope")
                if scope:
                    allowed = api.is_user_allowed(username, action, scope)
                    response_data.append({"action": action, "scope": scope, "allowed": allowed})
                else:
                    allowed = api.is_user_allowed_in_any_scope(username, action)
                    response_data.append({"action": action, "allowed": allowed})
            except ValueError as e:
                logger.error(f"Error validating permission for user {username}: {e}")
                return Response(data={"message": "Invalid scope format"}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error(f"Error validating permission for user {username}: {e}")
                return Response(
                    data={"message": "An error occurred while validating permissions"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        response_data, _ = PermissionValidationRequested.run_filter(items=response_data)
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
    - roles (Optional): Filter by comma-separated list of specific role names
    - page (Optional): Page number for pagination
    - page_size (Optional): Number of items per page
    - sort_by (Optional): Field to sort by (e.g., 'username', 'email', 'full_name')
    - order (Optional): Sort order ('asc' or 'desc')

    **Request Format (PUT)**

    - users: List of user identifiers (username or email)
    - role: The role to add users to
    - scope: The scope to add users to

    **Request Format (DELETE)**

    Query parameters:

    - users: Comma-separated list of user identifiers (username or email)
    - role: The role to remove users from
    - scope: The scope to remove users from

    **Response Format (GET)**

    Returns HTTP 200 OK with::

        {
            "count": 2,
            "next": null,
            "previous": null,
            "results": [
                {
                    "username": "john_doe",
                    "email": "john_doe@example.com",
                    "full_name": "John Doe"
                    "roles": ["library_admin", "library_user"]
                },
                {
                    "username": "jane_doe",
                    "email": "jane_doe@example.com",
                    "full_name": "Jane Doe"
                    "roles": ["library_user"]
                }
            ]
        }

    **Response Format (PUT)**

    Returns HTTP 207 Multi-Status with::

        {
            "completed": [{"user_identifier": "john_doe", "status": "role_added"}],
            "errors": [{"user_identifier": "jane_doe", "error": "user_already_has_role"}]
        }

    **Response Format (DELETE)**

    Returns HTTP 207 Multi-Status with::

        {
            "completed": [{"user_identifier": "john_doe", "status": "role_removed"}],
            "errors": [{"user_identifier": "jane_doe", "error": "user_does_not_have_role"}]
        }

    **Authentication and Permissions**

    - Requires authenticated user.

    - GET: Requires ``view_library_team`` or ``view_course_team`` permission according to the scope.
    - PUT and DELETE: Requires ``manage_library_team`` or ``manage_course_team`` permission according to the scope.

    **Example Request**

    GET /api/authz/v1/roles/users/?scope=lib:DemoX:CSPROB&search=john&roles=library_admin

    PUT /api/authz/v1/roles/users/ ::

        {
            "role": "library_admin",
            "scope": "lib:DemoX:CSPROB",
            "users": ["user1@example.com", "username2"]
        }

    DELETE /api/authz/v1/roles/users/?role=library_admin&scope=lib:DemoX:CSPROB&users=user1@example.com,username2
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
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated or does not have the required permissions",
        },
    )
    @authz_permissions([permissions.VIEW_LIBRARY.identifier, permissions.COURSES_VIEW_COURSE_TEAM.identifier])
    def get(self, request: HttpRequest) -> Response:
        """Retrieve all users with role assignments within a specific scope."""
        serializer = ListUsersInRoleWithScopeSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        query_params = serializer.validated_data

        user_role_assignments = api.get_all_user_role_assignments_in_scope(query_params["scope"])
        usernames = {assignment.subject.username for assignment in user_role_assignments}
        context = {"user_map": get_user_map(usernames)}
        serialized_data = UserRoleAssignmentSerializer(user_role_assignments, many=True, context=context)

        filtered_users = filter_users(serialized_data.data, query_params["search"], query_params["roles"])
        user_role_assignments = sort_users(filtered_users, query_params["sort_by"], query_params["order"])

        paginator = self.pagination_class()
        paginated_response_data = paginator.paginate_queryset(user_role_assignments, request)
        return paginator.get_paginated_response(paginated_response_data)

    @apidocs.schema(
        body=AddUsersToRoleWithScopeSerializer,
        responses={
            status.HTTP_207_MULTI_STATUS: "The users were added to the role",
            status.HTTP_400_BAD_REQUEST: "The request data is invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated or does not have the required permissions",
        },
    )
    @authz_permissions([permissions.MANAGE_LIBRARY_TEAM.identifier, permissions.COURSES_MANAGE_COURSE_TEAM.identifier])
    def put(self, request: HttpRequest) -> Response:
        """Assign multiple users to a specific role within one or more scopes."""
        serializer = AddUsersToRoleWithScopeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        data, errors = RoleAssignmentRequested.run_filter(items=data)
        completed = []
        for scope_value in data["scopes"]:
            for user_identifier in data["users"]:
                response_dict = {"user_identifier": user_identifier, "scope": scope_value}
                try:
                    user = get_user_by_username_or_email(user_identifier)
                    result = api.assign_role_to_user_in_scope(user.username, data["role"], scope_value)
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
                    logger.error(f"Error assigning role to user {user_identifier} in scope {scope_value}: {e}")
                    response_dict["error"] = RoleOperationError.ROLE_ASSIGNMENT_ERROR
                    errors.append(response_dict)

        response_data = {"completed": completed, "errors": errors}
        return Response(response_data, status=status.HTTP_207_MULTI_STATUS)

    @apidocs.schema(
        parameters=[
            apidocs.query_parameter(
                "users",
                str,
                description="List of user identifiers (username or email) separated by a comma",
            ),
            apidocs.query_parameter("role", str, description="The role to remove the users from"),
            apidocs.query_parameter("scope", str, description="The scope to remove the users from"),
        ],
        responses={
            status.HTTP_207_MULTI_STATUS: "The users were removed from the role",
            status.HTTP_400_BAD_REQUEST: "The request parameters are invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated or does not have the required permissions",
        },
    )
    @authz_permissions([permissions.MANAGE_LIBRARY_TEAM.identifier, permissions.COURSES_MANAGE_COURSE_TEAM.identifier])
    def delete(self, request: HttpRequest) -> Response:
        """Remove multiple users from a specific role within a scope."""
        serializer = RemoveUsersFromRoleWithScopeSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        data, errors = RoleRemovalRequested.run_filter(items=data)
        completed = []
        for user_identifier in data["users"]:
            response_dict = {"user_identifier": user_identifier}
            try:
                user = get_user_by_username_or_email(user_identifier)
                result = api.unassign_role_from_user(user.username, data["role"], data["scope"])
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
    """API view for retrieving the roles, permissions and categories of one or more scope types.

    Returns a catalog that lets the Admin Console build its roles and permissions matrix from a
    single request (ADR 0028). The roles are paginated; the ``categories`` and ``permissions``
    catalogs are complete in every page.

    **Endpoints**

    - GET: Retrieve the catalog for one or more scope types

    **Query Parameters**

    - scope_types (Required): Comma-separated list of scope types to query, with at least one value.
      Each one is ``course-v1`` or ``lib``.
    - page (Optional): Page number for pagination of the roles
    - page_size (Optional): Number of roles per page

    **Response Format**

    - count, next, previous: Pagination of the roles
    - scope_types: The requested scope types (``course-v1``, ``lib``)
    - categories: Categories used by the permissions (id, display_name, description, icon)
    - permissions: Permissions of the scope types (id, display_name, description, icon, category_id, scope_types)
    - results: Roles, each with role, display_name, description, icon, definition_kind, permissions
      (ids of entries of ``permissions``), scope_types (requested scope types in which the role has grants)

    **Authentication and Permissions**

    - Requires authenticated user.
    - ``course-v1`` requires ``courses.view_course_team`` in any scope.
    - ``lib`` requires ``content_libraries.view_library_team`` in any scope.
    - The user must hold the permission of each requested scope type.

    **Example Request**

    GET /api/authz/v1/roles/?scope_types=course-v1&page=1&page_size=10
    """

    pagination_class = AuthZAPIViewPagination
    permission_classes = [ScopeTypePermission]

    @apidocs.schema(
        parameters=[
            apidocs.query_parameter(
                "scope_types", str, description="Comma-separated scope types to query: `course-v1` and/or `lib`"
            ),
            apidocs.query_parameter("page", int, description="Page number for pagination"),
            apidocs.query_parameter("page_size", int, description="Number of roles per page"),
        ],
        responses={
            status.HTTP_200_OK: RoleCatalogResponseSerializer,
            status.HTTP_400_BAD_REQUEST: "The request parameters are invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated",
            status.HTTP_403_FORBIDDEN: "The user does not have the required permissions",
        },
    )
    def get(self, request: HttpRequest) -> Response:
        """Retrieve the roles, permissions and categories available for one or more scope types."""
        query_serializer = ListRolesQuerySerializer(data=request.query_params)
        query_serializer.is_valid(raise_exception=True)
        scope_types = query_serializer.validated_data["scope_types"]

        permission_catalog = api.get_permission_catalog(scope_types)
        role_catalog = api.get_role_catalog(scope_types)

        paginator = self.pagination_class()
        page = paginator.paginate_queryset(role_catalog, request)
        response = paginator.get_paginated_response(RoleCatalogRoleSerializer(page, many=True).data)
        response.data.update(
            RoleCatalogMetaSerializer(
                {
                    "scope_types": scope_types,
                    "categories": api.get_category_catalog(permission_catalog),
                    "permissions": permission_catalog,
                }
            ).data
        )
        return response


@view_auth_classes()
class UserValidationAPIView(APIView):
    """API view for validating that provided user identifiers correspond to existing users.

    This view allows clients to verify that a list of user identifiers (usernames or emails)
    correspond to valid users in the system. It is designed to support bulk validation of multiple
    user identifiers in a single request, providing a convenient way to check the validity of users before
    performing operations such as role assignments.

    **Endpoints**
    - POST: Validate that the provided list of usernames or emails correspond to existing users

    **Request Format (POST)**
    - users: List of user identifiers (username or email)

    **Response Format (POST)**

    Returns HTTP 200 OK with::

        {
            "valid_users": ["john_doe", "jane@example.com"],
            "invalid_users": ["nonexistent_user"],
            "summary": {
                "total": 3,
                "valid_count": 2,
                "invalid_count": 1
            }
        }

    **Authentication and Permissions**

    - Requires authenticated user.
    - Requires ``manage_library_team`` or ``manage_course_team`` permission in any scope.

    **Example Request**

    POST /api/authz/v1/users/validate/ ::

        {
            "users": ["john_doe", "jane@example.com", "nonexistent_user"]
        }
    """

    permission_classes = [AnyScopePermission]

    @apidocs.schema(
        body=UserValidationAPIViewSerializer,
        responses={
            status.HTTP_200_OK: UserValidationAPIViewResponseSerializer,
            status.HTTP_400_BAD_REQUEST: "The request data is invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated",
            status.HTTP_403_FORBIDDEN: "The user does not have the required permissions",
            status.HTTP_500_INTERNAL_SERVER_ERROR: "An unexpected error occurred while validating users",
        },
    )
    @authz_permissions([permissions.MANAGE_LIBRARY_TEAM.identifier, permissions.COURSES_MANAGE_COURSE_TEAM.identifier])
    def post(self, request: HttpRequest) -> Response:
        """Validates the provided usernames or emails correspond to existing users."""
        request_serializer = UserValidationAPIViewSerializer(data=request.data)
        request_serializer.is_valid(raise_exception=True)
        serialized_request_users = request_serializer.validated_data["users"]
        try:
            valid_users, invalid_users = api.validate_users(serialized_request_users)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error(f"Error validating users: {e}")
            return Response(
                data={"message": "An error occurred while validating users"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        response_data = {
            "valid_users": valid_users,
            "invalid_users": invalid_users,
            "summary": {
                "total": len(serialized_request_users),
                "valid_count": len(valid_users),
                "invalid_count": len(invalid_users),
            },
        }
        response_serializer = UserValidationAPIViewResponseSerializer(response_data)
        return Response(response_serializer.data, status=status.HTTP_200_OK)
