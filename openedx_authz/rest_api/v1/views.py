"""
REST API views for Open edX Authorization (AuthZ) system.

This module provides Django REST Framework views for managing authorization
permissions, roles, and user assignments within Open edX platform.
"""

import logging

import edx_api_doc_tools as apidocs
from django.contrib.auth import get_user_model
from django.db.models import QuerySet
from django.http import HttpRequest
from django.utils.decorators import method_decorator
from edx_api_doc_tools import schema_for
from organizations.models import Organization
from organizations.serializers import OrganizationSerializer
from rest_framework import filters, generics, status
from rest_framework.response import Response
from rest_framework.views import APIView

from openedx_authz import api
from openedx_authz.api.data import RoleAssignmentData, SuperAdminAssignmentData
from openedx_authz.api.users import (
    get_superadmin_assignments,
    get_visible_user_role_assignments_filtered_by_current_user,
)
from openedx_authz.api.utils import get_user_map
from openedx_authz.constants import permissions
from openedx_authz.rest_api.data import RoleOperationError, RoleOperationStatus
from openedx_authz.rest_api.decorators import authz_permissions, view_auth_classes
from openedx_authz.rest_api.utils import (
    filter_users,
    get_generic_scope,
    sort_users,
)
from openedx_authz.rest_api.v1.filters import (
    TeamMemberAssignmentsOrderingFilter,
    TeamMemberOrderingFilter,
    TeamMemberSearchFilter,
)
from openedx_authz.rest_api.v1.paginators import AuthZAPIViewPagination
from openedx_authz.rest_api.v1.permissions import AnyScopePermission, DynamicScopePermission
from openedx_authz.rest_api.v1.serializers import (
    AddUsersToRoleWithScopeSerializer,
    ListRolesWithScopeResponseSerializer,
    ListRolesWithScopeSerializer,
    ListTeamMemberAssignmentsSerializer,
    ListTeamMembersSerializer,
    ListUsersInRoleWithScopeSerializer,
    PermissionValidationResponseSerializer,
    PermissionValidationSerializer,
    RemoveUsersFromRoleWithScopeSerializer,
    TeamMemberAssignmentSerializer,
    TeamMemberSerializer,
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
    - scope: The authorization scope (e.g., 'lib:DemoX:CSPROB')

    **Response Format**

    Returns a list of validation results, each containing:

    - action: The requested action
    - scope: The requested scope
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
                scope = permission["scope"]
                allowed = api.is_user_allowed(username, action, scope)
                response_data.append({"action": action, "scope": scope, "allowed": allowed})
            except ValueError as e:
                logger.error(f"Error validating permission for user {username}: {e}")
                return Response(data={"message": "Invalid scope format"}, status=status.HTTP_400_BAD_REQUEST)
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
    - Requires ``manage_library_team`` permission for the scope.

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
    @authz_permissions([permissions.VIEW_LIBRARY.identifier])
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
    @authz_permissions([permissions.MANAGE_LIBRARY_TEAM.identifier])
    def put(self, request: HttpRequest) -> Response:
        """Assign multiple users to a specific role within a scope."""
        serializer = AddUsersToRoleWithScopeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        completed, errors = [], []
        for user_identifier in data["users"]:
            response_dict = {"user_identifier": user_identifier}
            try:
                user = get_user_by_username_or_email(user_identifier)
                result = api.assign_role_to_user_in_scope(user.username, data["role"], data["scope"])
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
    @authz_permissions([permissions.MANAGE_LIBRARY_TEAM.identifier])
    def delete(self, request: HttpRequest) -> Response:
        """Remove multiple users from a specific role within a scope."""
        serializer = RemoveUsersFromRoleWithScopeSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        completed, errors = [], []
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
    """API view for retrieving role definitions and their associated permissions within a specific scope.

    This view provides read-only access to role definitions within a specific
    authorization scope. It returns detailed information about each role including
    the permissions granted and the number of users assigned to each role.

    **Endpoints**

    - GET: Retrieve all roles and their permissions for a specific scope

    **Query Parameters**

    - scope (Required): The scope to query roles for (e.g., 'lib:OpenedX:CSPROB')
    - page (Optional): Page number for pagination
    - page_size (Optional): Number of items per page

    **Response Format**

    Returns a paginated list of role objects, each containing:

    - role: The role's external identifier (e.g., 'library_author', 'library_user')
    - permissions: List of permission identifiers granted by this role (e.g., 'content_libraries.delete_library')
    - user_count: Number of users currently assigned to this role

    **Authentication and Permissions**

    - Requires authenticated user.
    - Requires ``manage_library_team`` permission for the scope.

    **Example Request**

    GET /api/authz/v1/roles/?scope=lib:OpenedX:CSPROB&page=1&page_size=10

    **Example Response**::

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
    permission_classes = [DynamicScopePermission]

    @apidocs.schema(
        parameters=[
            apidocs.query_parameter("scope", str, description="The scope to query roles for"),
            apidocs.query_parameter("page", int, description="Page number for pagination"),
            apidocs.query_parameter("page_size", int, description="Number of items per page"),
        ],
        responses={
            status.HTTP_200_OK: ListRolesWithScopeResponseSerializer(many=True),
            status.HTTP_400_BAD_REQUEST: "The request parameters are invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated or does not have the required permissions",
        },
    )
    @authz_permissions([permissions.VIEW_LIBRARY.identifier])
    def get(self, request: HttpRequest) -> Response:
        """Retrieve all roles and their permissions for a specific scope."""
        serializer = ListRolesWithScopeSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        query_params = serializer.validated_data

        generic_scope = get_generic_scope(query_params["scope"])
        roles = api.get_role_definitions_in_scope(generic_scope)
        response_data = []
        for role in roles:
            users = api.get_users_for_role_in_scope(role.external_key, query_params["scope"].external_key)
            response_data.append(
                {
                    "role": role.external_key,
                    "permissions": role.get_permission_identifiers(),
                    "user_count": len(users),
                }
            )

        paginator = self.pagination_class()
        paginated_response_data = paginator.paginate_queryset(response_data, request)
        serialized_data = ListRolesWithScopeResponseSerializer(paginated_response_data, many=True)
        return paginator.get_paginated_response(serialized_data.data)


@view_auth_classes()
@method_decorator(
    authz_permissions(
        [
            permissions.VIEW_LIBRARY_TEAM.identifier,
            permissions.COURSES_VIEW_COURSE_TEAM.identifier,
        ]
    ),
    name="get",
)
@schema_for(
    "get",
    parameters=[
        apidocs.query_parameter("search", str, description="Filter orgs by name or short_name"),
        apidocs.query_parameter("page", int, description="Page number for pagination"),
        apidocs.query_parameter("page_size", int, description="Number of items per page"),
    ],
    responses={
        status.HTTP_200_OK: OrganizationSerializer(many=True),
        status.HTTP_401_UNAUTHORIZED: "The user is not authenticated",
    },
)
class AdminConsoleOrgsAPIView(generics.ListAPIView):
    """
    API view for listing orgs
    This API is used on the filters functionality on the Admin Console.

    **Endpoints**

    - GET: Retrieve all organizations

    **Query Parameters**

    - search (Optional): Search term to filter organizations by name or short name
    - page (Optional): Page number for pagination
    - page_size (Optional): Number of items per page

    **Response Format**

    Returns a paginated list of organization objects, each containing:

    - id: The organization's ID
    - name: The organization's name
    - short_name: The organization's short name

    **Authentication and Permissions**

    - Requires authenticated user.

    **Example Request**

    GET /api/authz/v1/orgs/?search=edx&page=1&page_size=10

    **Example Response**::

        {
            "count": 1,
            "next": null,
            "previous": null,
            "results": [
                {
                    "id": 1,
                    "created": "2026-04-02T19:30:36.779095Z",
                    "modified": "2026-04-02T19:30:36.779095Z",
                    "name": "OpenedX",
                    "short_name": "OpenedX",
                    "description": "",
                    "logo": null,
                    "active": true
                }
            ]
        }
    """

    serializer_class = OrganizationSerializer
    pagination_class = AuthZAPIViewPagination
    filter_backends = [filters.SearchFilter]
    search_fields = ["name", "short_name"]
    permission_classes = [AnyScopePermission]

    def get_queryset(self) -> QuerySet:
        """Return active organizations ordered by name."""
        return Organization.objects.filter(active=True).order_by("name")


@view_auth_classes()
class TeamMembersAPIView(APIView):
    """
    API view for listing users in relation to role assignments
    This API is used in the Team Members section in Admin Console.
    In this content, a team member is anyone with studio access.
    """

    pagination_class = AuthZAPIViewPagination
    filter_backends = [TeamMemberSearchFilter, TeamMemberOrderingFilter]

    @apidocs.schema(
        parameters=[
            apidocs.query_parameter("scopes", str, description="The scopes to query assignments for"),
            apidocs.query_parameter("orgs", str, description="The orgs to query assignments for"),
            apidocs.query_parameter("search", str, description="The search query to filter users by"),
            apidocs.query_parameter("sort_by", str, description="The field to sort by"),
            apidocs.query_parameter("order", str, description="The order to sort by"),
            apidocs.query_parameter("page", int, description="Page number for pagination"),
            apidocs.query_parameter("page_size", int, description="Number of items per page"),
        ],
        responses={
            status.HTTP_200_OK: ListRolesWithScopeResponseSerializer(many=True),
            status.HTTP_400_BAD_REQUEST: "The request parameters are invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated or does not have the required permissions",
        },
    )
    def get(self, request: HttpRequest) -> Response:
        """Retrieve all users that have at least one assignation according to the filtering fields."""
        serializer = ListTeamMembersSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        query_params = serializer.validated_data

        users_with_assignments = api.get_visible_role_assignments_for_user(
            orgs=query_params.get("orgs"),
            scopes=query_params.get("scopes"),
            allowed_for_user_external_key=request.user.username,
        )

        team_members = TeamMemberSerializer(users_with_assignments, many=True).data
        for backend in self.filter_backends:
            team_members = backend().filter_queryset(request, team_members, self)

        paginator = self.pagination_class()
        paginated_response_data = paginator.paginate_queryset(team_members, request)
        return paginator.get_paginated_response(paginated_response_data)


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


@view_auth_classes()
class TeamMemberAssignmentsAPIView(APIView):
    """
    API view for listing user role assignments
    """

    pagination_class = AuthZAPIViewPagination
    filter_backends = [TeamMemberAssignmentsOrderingFilter]

    @apidocs.schema(
        parameters=[
            apidocs.query_parameter("orgs", str, description="The orgs to query assignations for"),
            apidocs.query_parameter("roles", str, description="The roles to query assignations for"),
            apidocs.query_parameter("sort_by", str, description="The field to sort by"),
            apidocs.query_parameter("order", str, description="The order to sort by"),
            apidocs.query_parameter("page", int, description="Page number for pagination"),
            apidocs.query_parameter("page_size", int, description="Number of items per page"),
        ],
        responses={
            status.HTTP_200_OK: TeamMemberAssignmentSerializer(many=True),
            status.HTTP_400_BAD_REQUEST: "The request parameters are invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated or does not have the required permissions",
        },
    )
    def get(self, request: HttpRequest, username: str) -> Response:
        """Retrieve all user role assignments."""
        serializer = ListTeamMemberAssignmentsSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        query_params = serializer.validated_data

        user_role_assignments: list[RoleAssignmentData | SuperAdminAssignmentData] = []

        # Retrieve superadmin assignments (django staff or superuser users), as they always have access to everything
        user_role_assignments += get_superadmin_assignments(user_external_keys=[username])

        user_role_assignments += get_visible_user_role_assignments_filtered_by_current_user(
            user_external_key=username,
            orgs=query_params.get("orgs"),
            roles=query_params.get("roles"),
            allowed_for_user_external_key=request.user.username,
        )

        assignments = TeamMemberAssignmentSerializer(user_role_assignments, many=True).data
        for backend in self.filter_backends:
            assignments = backend().filter_queryset(request, assignments, self)

        # Paginate
        paginator = self.pagination_class()
        paginated_response_data = paginator.paginate_queryset(assignments, request)
        return paginator.get_paginated_response(paginated_response_data)
