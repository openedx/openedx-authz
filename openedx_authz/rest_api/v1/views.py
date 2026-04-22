"""
REST API views for Open edX Authorization (AuthZ) system.

This module provides Django REST Framework views for managing authorization
permissions, roles, and user assignments within Open edX platform.
"""

import logging
import operator
from functools import reduce

import edx_api_doc_tools as apidocs
from django.contrib.auth import get_user_model
from django.db.models import CharField, Q, QuerySet, Value
from django.db.models.functions import Cast
from django.http import HttpRequest
from django.utils.decorators import method_decorator
from edx_api_doc_tools import schema_for
from organizations.models import Organization
from organizations.serializers import OrganizationSerializer
from rest_framework import filters, generics, status
from rest_framework.response import Response
from rest_framework.views import APIView

from openedx_authz import api
from openedx_authz.api.data import (
    ContentLibraryData,
    CourseOverviewData,
    OrgContentLibraryGlobData,
    OrgCourseOverviewGlobData,
    RoleAssignmentData,
    SuperAdminAssignmentData,
    UserAssignmentData,
)
from openedx_authz.api.users import (
    get_scopes_for_user_and_permission,
    get_superadmin_assignments,
    get_visible_user_role_assignments_filtered_by_current_user,
)
from openedx_authz.api.utils import get_user_map
from openedx_authz.constants import permissions
from openedx_authz.models.scopes import get_content_library_model, get_course_overview_model
from openedx_authz.rest_api.data import RoleOperationError, RoleOperationStatus, ScopesQuerySetFields, ScopesTypeField
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
    UserAssignmentsOrderingFilter,
    UserAssignmentsSearchFilter,
)
from openedx_authz.rest_api.v1.paginators import AuthZAPIViewPagination
from openedx_authz.rest_api.v1.permissions import AnyScopePermission, DynamicScopePermission
from openedx_authz.rest_api.v1.serializers import (
    AddUsersToRoleWithScopeSerializer,
    ListAssignmentsQuerySerializer,
    ListRolesWithScopeResponseSerializer,
    ListRolesWithScopeSerializer,
    ListScopesQuerySerializer,
    ListTeamMemberAssignmentsQuerySerializer,
    ListTeamMembersSerializer,
    ListUsersInRoleWithScopeSerializer,
    PermissionValidationResponseSerializer,
    PermissionValidationSerializer,
    RemoveUsersFromRoleWithScopeSerializer,
    ScopeSerializer,
    TeamMemberAssignmentSerializer,
    TeamMemberSerializer,
    TeamMemberUserAssignmentSerializer,
    UserRoleAssignmentSerializer,
    UserValidationAPIViewResponseSerializer,
    UserValidationAPIViewSerializer,
)
from openedx_authz.utils import get_user_by_username_or_email

logger = logging.getLogger(__name__)

User = get_user_model()
ContentLibrary = get_content_library_model()
CourseOverview = get_course_overview_model()


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
        """Assign multiple users to a specific role within one or more scopes."""
        serializer = AddUsersToRoleWithScopeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        completed, errors = [], []
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
        status.HTTP_403_FORBIDDEN: "The user does not have the required permissions",
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
        apidocs.query_parameter("search", str, description="Filter scopes by display name"),
        apidocs.query_parameter("org", str, description="Filter scopes by org"),
        apidocs.query_parameter(
            "orgs", str, description="Filter scopes by multiple orgs (comma separated list of orgs)"
        ),
        apidocs.query_parameter("page", int, description="Page number for pagination"),
        apidocs.query_parameter("page_size", int, description="Number of items per page"),
        apidocs.query_parameter(
            "management_permission_only",
            bool,
            description=(
                "If true, returns only scopes to which the calling user has manage team permission, "
                "otherwise, returns any scope to which the user has view team permission."
            ),
        ),
        apidocs.query_parameter(
            "scope_type",
            str,
            description="Filter by scope type. Either 'course' or 'library'. Returns both if not specified.",
        ),
    ],
    responses={
        status.HTTP_200_OK: ScopeSerializer(many=True),
        status.HTTP_400_BAD_REQUEST: "The request parameters are invalid",
        status.HTTP_401_UNAUTHORIZED: "The user is not authenticated",
        status.HTTP_403_FORBIDDEN: "The user does not have the required permissions",
    },
)
class ScopesAPIView(generics.ListAPIView):
    """
    API view for listing scopes
    This API is used on the filters and assign roles functionality on the Admin Console.

    **Endpoints**

    - GET: Retrieve all scopes

    **Query Parameters**

    - search (Optional): Search term to filter scopes by display name
    - org (Optional): Filter scopes by org
    - orgs (Optional): Filter scopes by multiple orgs (comma separated list of orgs)
    - page (Optional): Page number for pagination
    - page_size (Optional): Number of items per page
    - scope_type (Optional): Filter scopes by type. Supported values are `course` and `library`.
    - management_permission_only (Optional): Filter scopes either by only the ones to which the user has "manage team"
        permissions (if true), or just "view team" permissions.

    **Response Format**

    Returns a paginated list of scope objects, each containing:

    - external_key: The scope external key
    - display_name: The scope's name
    - org: The organization serialized object

    **Authentication and Permissions**

    - Requires authenticated user with either a content library or course view team permission.

    **Example Request**

    GET /api/authz/v1/scopes/?search=edx&page=1&page_size=10

    **Example Response**::

        {
            "count": 1,
            "next": null,
            "previous": null,
            "results": [
                {
                    "external_key": "course-v1:OpenedX+DemoX+DemoCourse",
                    "display_name": "Open edX Demo Course",
                    "org": {
                        "id": 1,
                        "created": "2026-04-02T19:30:36.779095Z",
                        "modified": "2026-04-02T19:30:36.779095Z",
                        "name": "OpenedX",
                        "short_name": "OpenedX",
                        "description": "",
                        "logo": null,
                        "active": true
                    }
                },
            ]
        }
    """

    serializer_class = ScopeSerializer
    pagination_class = AuthZAPIViewPagination
    permission_classes = [AnyScopePermission]

    # Priority for fields used for stable sorting (first has more priority)
    ordering_priority = (
        ScopesQuerySetFields.ORG_NAME,
        ScopesQuerySetFields.SCOPE_TYPE,
        ScopesQuerySetFields.DISPLAY_NAME_COL,
        ScopesQuerySetFields.SCOPE_ID,
    )

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["org_map"] = Organization.objects.filter(active=True).in_bulk(field_name="short_name")
        return context

    def _get_courses_queryset(
        self,
        allowed_ids: set | None = None,
        allowed_orgs: set | None = None,
        search: str = "",
        orgs: set[str] | None = None,
    ) -> QuerySet:
        """Return a CourseOverview queryset projected to the unified scope shape.

        If allowed_ids and/or allowed_orgs are provided, filter to matching courses.
        If search is provided, filter by display_name.
        If org is provided, filter by org short_name.
        """
        qs = CourseOverview.objects
        if allowed_ids is not None or allowed_orgs is not None:
            org_filter = Q(org__in=allowed_orgs) if allowed_orgs else Q()
            id_filter = Q(id__in=allowed_ids) if allowed_ids else Q()
            combined_filter = org_filter | id_filter
            if not combined_filter:
                qs = qs.none()
            else:
                qs = qs.filter(combined_filter)
        if orgs:
            qs = qs.filter(org__in=orgs)
        if search:
            qs = qs.filter(display_name__icontains=search)
        return qs.annotate(
            scope_id=Cast("id", output_field=CharField(db_collation="utf8mb4_unicode_ci")),
            display_name_col=Cast("display_name", output_field=CharField(db_collation="utf8mb4_unicode_ci")),
            org_name=Cast("org", output_field=CharField(db_collation="utf8mb4_unicode_ci")),
            scope_type=Value(ScopesTypeField.COURSE, output_field=CharField(db_collation="utf8mb4_unicode_ci")),
        ).values(
            ScopesQuerySetFields.SCOPE_ID,
            ScopesQuerySetFields.DISPLAY_NAME_COL,
            ScopesQuerySetFields.ORG_NAME,
            ScopesQuerySetFields.SCOPE_TYPE,
        )

    def _get_libraries_queryset(
        self,
        allowed_pairs: set | None = None,
        allowed_orgs: set | None = None,
        search: str = "",
        orgs: set[str] | None = None,
    ) -> QuerySet:
        """Return a ContentLibrary queryset projected to the unified scope shape.

        If allowed_pairs and/or allowed_orgs are provided, filter to matching libraries.
        If search is provided, filter by learning_package__title.
        If org is provided, filter by org short_name.
        """
        qs = ContentLibrary.objects
        if allowed_pairs is not None or allowed_orgs is not None:
            org_filter = Q(org__short_name__in=allowed_orgs) if allowed_orgs else Q()
            pair_filter = (
                reduce(operator.or_, (Q(org__short_name=org, slug=slug) for org, slug in allowed_pairs))
                if allowed_pairs
                else Q()
            )
            combined = org_filter | pair_filter
            if not combined:
                qs = qs.none()
            else:
                qs = qs.filter(combined)
        if orgs:
            qs = qs.filter(org__short_name__in=orgs)
        if search:
            qs = qs.filter(learning_package__title__icontains=search)
        return qs.annotate(
            scope_id=Cast("slug", output_field=CharField(db_collation="utf8mb4_unicode_ci")),
            display_name_col=Cast("learning_package__title", output_field=CharField(db_collation="utf8mb4_unicode_ci")),
            org_name=Cast("org__short_name", output_field=CharField(db_collation="utf8mb4_unicode_ci")),
            scope_type=Value(ScopesTypeField.LIBRARY, output_field=CharField(db_collation="utf8mb4_unicode_ci")),
        ).values(
            ScopesQuerySetFields.SCOPE_ID,
            ScopesQuerySetFields.DISPLAY_NAME_COL,
            ScopesQuerySetFields.ORG_NAME,
            ScopesQuerySetFields.SCOPE_TYPE,
        )

    @staticmethod
    def _get_allowed_scope_queryset(
        *,
        username: str,
        scope_cls: type,
        glob_cls: type,
        get_permission: callable,
        queryset_builder: callable,
        extract_ids: callable,
        search: str = "",
        orgs: set[str] | None = None,
    ) -> QuerySet:
        """Resolve allowed scopes from Casbin and return a filtered queryset.

        This helper encapsulates the shared pattern of:
        1. Fetching allowed scopes for a user and permission.
        2. Partitioning them into specific IDs vs org-level globs.
        3. Delegating to the appropriate queryset builder.

        Args:
            username: The username to check permissions for.
            scope_cls: The concrete scope data class (e.g., CourseOverviewData).
            glob_cls: The org-level glob class (e.g., OrgCourseOverviewGlobData).
            get_permission: Callable that returns the permission for a scope class.
            queryset_builder: Callable that builds the filtered queryset (e.g., _get_courses_queryset).
            extract_ids: Callable that extracts specific IDs from non-glob scopes.
            search: Optional search term to filter by display name.
            org: Optional org short_name to filter by.

        Returns:
            QuerySet: The filtered queryset projected to the unified scope shape.
        """
        allowed_scopes = get_scopes_for_user_and_permission(username, get_permission(scope_cls).identifier)
        specific_scopes = [s for s in allowed_scopes if not isinstance(s, glob_cls)]
        allowed_ids = extract_ids(specific_scopes)
        allowed_orgs = {s.org for s in allowed_scopes if isinstance(s, glob_cls)}
        return queryset_builder(allowed_ids, allowed_orgs, search=search, orgs=orgs)

    def _build_queryset(self, courses_qs: QuerySet | None, libraries_qs: QuerySet | None) -> QuerySet:
        """Union the provided querysets and sort deterministically.

        Orders by org_name first (satisfying the 'ordered by org' requirement), then by
        scope_type, display_name_col, and scope_id as tiebreakers to ensure stable pagination.
        """
        if courses_qs is not None and libraries_qs is not None:
            return courses_qs.union(libraries_qs).order_by(*self.ordering_priority)
        qs = courses_qs if courses_qs is not None else libraries_qs
        return qs.order_by(*self.ordering_priority)

    def get_queryset(self) -> QuerySet:
        """Return scopes ordered by org, filtered by the user's permissions."""
        user = self.request.user

        # Validate and parse query parameters.
        params_serializer = ListScopesQuerySerializer(data=self.request.query_params)
        params_serializer.is_valid(raise_exception=True)
        scope_type = params_serializer.validated_data["scope_type"]
        search = params_serializer.validated_data["search"]
        org = params_serializer.validated_data.get("org", "")
        orgs_param = params_serializer.validated_data.get("orgs", [])

        orgs = set()
        orgs.update(orgs_param)

        if org:
            orgs.add(org)

        # Staff and superusers can see all scopes, skip permission filtering.
        if user.is_staff or user.is_superuser:
            return self._build_queryset(
                courses_qs=(
                    self._get_courses_queryset(search=search, orgs=orgs)
                    if scope_type != ScopesTypeField.LIBRARY
                    else None
                ),
                libraries_qs=(
                    self._get_libraries_queryset(search=search, orgs=orgs)
                    if scope_type != ScopesTypeField.COURSE
                    else None
                ),
            )

        management_only = params_serializer.validated_data["management_permission_only"]

        # Determine which permission to check based on the query parameter.
        def get_permission(scope_cls):
            return scope_cls.get_admin_manage_permission() if management_only else scope_cls.get_admin_view_permission()

        # Resolve allowed scopes from Casbin and build filtered querysets.
        courses_qs = None
        if scope_type != ScopesTypeField.LIBRARY:
            courses_qs = self._get_allowed_scope_queryset(
                username=user.username,
                scope_cls=CourseOverviewData,
                glob_cls=OrgCourseOverviewGlobData,
                get_permission=get_permission,
                queryset_builder=self._get_courses_queryset,
                extract_ids=lambda scopes: {s.external_key for s in scopes},
                search=search,
                orgs=orgs,
            )

        libraries_qs = None
        if scope_type != ScopesTypeField.COURSE:
            libraries_qs = self._get_allowed_scope_queryset(
                username=user.username,
                scope_cls=ContentLibraryData,
                glob_cls=OrgContentLibraryGlobData,
                get_permission=get_permission,
                queryset_builder=self._get_libraries_queryset,
                extract_ids=lambda scopes: {
                    (s.external_key.split(":")[1], s.external_key.split(":")[2]) for s in scopes
                },
                search=search,
                orgs=orgs,
            )

        # Union the requested querysets and sort by org at the DB level.
        return self._build_queryset(courses_qs, libraries_qs)


@view_auth_classes()
class TeamMembersAPIView(APIView):
    """
    API view for listing users in relation to role assignments.
    This API is used in the Team Members section in the Admin Console.
    In this context, a team member is anyone with studio access.

    **Endpoints**

    - GET: Retrieve all users that have at least one role assignment

    **Query Parameters**

    - scopes (Optional): Comma-separated list of scopes to filter by (e.g., 'lib:Org1:LIB1')
    - orgs (Optional): Comma-separated list of orgs to filter by (e.g., 'Org1,Org2')
    - search (Optional): Search term to filter users by username, full name, or email
    - sort_by (Optional): Field to sort by. Options: username, full_name, email. Defaults to username
    - order (Optional): Sort order, 'asc' or 'desc'. Defaults to asc
    - page (Optional): Page number for pagination
    - page_size (Optional): Number of items per page

    **Response Format**

    Returns a paginated list of team member objects, each containing:

    - username: The user's username
    - full_name: The user's full name
    - email: The user's email address
    - assignation_count: The number of role assignments the user has

    **Authentication and Permissions**

    - Requires authenticated user.
    - Results are filtered according to calling user's scope-level view permissions.

    **Example Request**

    GET /api/authz/v1/users/?orgs=Org1&search=john&sort_by=username&order=asc&page=1&page_size=10

    **Example Response**::

        {
            "count": 2,
            "next": null,
            "previous": null,
            "results": [
                {
                    "username": "jane_doe",
                    "full_name": "Jane Doe",
                    "email": "jane_doe@example.com",
                    "assignation_count": 3
                },
                {
                    "username": "john_doe",
                    "full_name": "John Doe",
                    "email": "john_doe@example.com",
                    "assignation_count": 1
                }
            ]
        }
    """

    pagination_class = AuthZAPIViewPagination
    filter_backends = [TeamMemberSearchFilter, TeamMemberOrderingFilter]
    permission_classes = [AnyScopePermission]

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
            status.HTTP_200_OK: TeamMemberSerializer(many=True),
            status.HTTP_400_BAD_REQUEST: "The request parameters are invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated",
            status.HTTP_403_FORBIDDEN: "The user does not have the required permissions",
        },
    )
    @authz_permissions(
        [
            permissions.VIEW_LIBRARY_TEAM.identifier,
            permissions.COURSES_VIEW_COURSE_TEAM.identifier,
        ]
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
    API view for listing role assignments for a specific user.
    This API is used in the Team Member detail view in the Admin Console.

    **Endpoints**

    - GET: Retrieve all role assignments for a specific user

    **URL Parameters**

    - username (Required): The username of the user to retrieve assignments for

    **Query Parameters**

    - orgs (Optional): Comma-separated list of orgs to filter assignments by (e.g., 'Org1,Org2')
    - roles (Optional): Comma-separated list of roles to filter assignments by (e.g., 'library_admin,library_user')
    - sort_by (Optional): Field to sort by. Options: role, org, scope. Defaults to role
    - order (Optional): Sort order, 'asc' or 'desc'. Defaults to asc
    - page (Optional): Page number for pagination
    - page_size (Optional): Number of items per page

    **Response Format**

    Returns a paginated list of assignment objects, each containing:

    - is_superadmin: Whether this entry denotes a superadmin (staff/superuser)
    - role: The role name (e.g., 'library_admin', 'django.superuser')
    - org: The org over which this role is applied ('*' for superadmins)
    - scope: The scope over which this role is applied ('*' for superadmins)
    - permission_count: The number of permissions that apply to this role (null for superadmins)

    **Authentication and Permissions**

    - Requires authenticated user.
    - Results are filtered according to calling user's scope-level view permissions.
    - Superadmin entries are always included when the target user is a staff/superuser.

    **Example Request**

    GET
    /api/authz/v1/users/john_doe/assignments/?orgs=Org1&roles=library_admin&sort_by=role&order=asc&page=1&page_size=10

    **Example Response**::

        {
            "count": 2,
            "next": null,
            "previous": null,
            "results": [
                {
                    "is_superadmin": true,
                    "role": "django.superuser",
                    "org": "*",
                    "scope": "*",
                    "permission_count": null
                },
                {
                    "is_superadmin": false,
                    "role": "library_admin",
                    "org": "Org1",
                    "scope": "lib:Org1:LIB1",
                    "permission_count": 11
                }
            ]
        }
    """

    pagination_class = AuthZAPIViewPagination
    filter_backends = [TeamMemberAssignmentsOrderingFilter]
    permission_classes = [AnyScopePermission]

    @apidocs.schema(
        parameters=[
            apidocs.query_parameter("orgs", str, description="Comma-separated list of orgs to filter assignments by"),
            apidocs.query_parameter("roles", str, description="Comma-separated list of roles to filter assignments by"),
            apidocs.query_parameter(
                "sort_by",
                str,
                description="The field to sort by. Options: role, org, scope. Defaults to role",
            ),
            apidocs.query_parameter(
                "order", str, description="The order to sort by. Options: asc, desc. Defaults to asc"
            ),
            apidocs.query_parameter("page", int, description="Page number for pagination"),
            apidocs.query_parameter("page_size", int, description="Number of items per page"),
        ],
        responses={
            status.HTTP_200_OK: TeamMemberAssignmentSerializer(many=True),
            status.HTTP_400_BAD_REQUEST: "The request parameters are invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated",
            status.HTTP_403_FORBIDDEN: "The user does not have the required permissions",
        },
    )
    @authz_permissions(
        [
            permissions.VIEW_LIBRARY_TEAM.identifier,
            permissions.COURSES_VIEW_COURSE_TEAM.identifier,
        ]
    )
    def get(self, request: HttpRequest, username: str) -> Response:
        """Retrieve all user role assignments."""
        serializer = ListTeamMemberAssignmentsQuerySerializer(data=request.query_params)
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


@view_auth_classes()
class AssignmentsAPIView(APIView):
    """
    API view for listing all user role assignments
    This API is used on the main team members view on the Admin Console.

    **Endpoints**

    - GET: Retrieve all user role assignments

    **Query Parameters**

    - orgs (Optional): Comma-separated list of orgs to filter assignments by
    - roles (Optional): Comma-separated list of roles to filter assignments by
    - scopes (Optional): Comma-separated list of scopes to filter assignments by
    - search (Optional): Search term to filter assignments by full_name, username, or email
    - sort_by (Optional): Field to sort by. Options: role, org, scope, full_name, username, email. Defaults to full_name
    - order (Optional): Sort order, 'asc' or 'desc'. Defaults to asc
    - page (Optional): Page number for pagination
    - page_size (Optional): Number of items per page

    **Response Format**

    Returns a paginated list of user assignment objects, each containing:

    - is_superadmin: whether this entry denotes a superadmin
    - role: The role
    - org: The org over which this role is applied
    - scope: The scope over which this role is applied
    - permission_count: The number of permissions that apply to this role
    - full_name: The full name of the user in this assignment
    - username: The username of the user in this assignment
    - email: The email of the user in this assignment

    **Authentication and Permissions**

    - Requires authenticated user.
    - Results are filtered according to calling user's "view scope team members" permissions.

    **Example Request**

    GET /api/authz/v1/assignments/?order=desc&sort_by=role&page=1&page_size=2&search=cont

    **Example Response**::

        {
            "count": 2,
            "next": null,
            "previous": null,
            "results": [
                {
                    "is_superadmin": false,
                    "role": "course_staff",
                    "org": "OpenedX",
                    "scope": "course-v1:OpenedX+DemoX+DemoCourse",
                    "permission_count": 27,
                    "full_name": "",
                    "username": "contributor",
                    "email": "contributor@example.com"
                },
                {
                    "is_superadmin": true,
                    "role": "django.superuser",
                    "org": "*",
                    "scope": "*",
                    "permission_count": null,
                    "full_name": "",
                    "username": "admin",
                    "email": "admin@example.com"
                },
            ]
        }
    """

    pagination_class = AuthZAPIViewPagination
    filter_backends = [UserAssignmentsSearchFilter, UserAssignmentsOrderingFilter]
    permission_classes = [AnyScopePermission]

    @apidocs.schema(
        parameters=[
            apidocs.query_parameter("orgs", str, description="The orgs to query assignments for"),
            apidocs.query_parameter("roles", str, description="The roles to query assignments for"),
            apidocs.query_parameter("scopes", str, description="The scopes to query assignments for"),
            apidocs.query_parameter(
                "search", str, description="The search query to filter assignments by full_name, username, or email"
            ),
            apidocs.query_parameter(
                "sort_by",
                str,
                description="The field to sort by. Options: role, org, scope, full_name, username, email",
            ),
            apidocs.query_parameter("order", str, description="The order to sort by"),
            apidocs.query_parameter("page", int, description="Page number for pagination"),
            apidocs.query_parameter("page_size", int, description="Number of items per page"),
        ],
        responses={
            status.HTTP_200_OK: TeamMemberUserAssignmentSerializer(many=True),
            status.HTTP_400_BAD_REQUEST: "The request parameters are invalid",
            status.HTTP_401_UNAUTHORIZED: "The user is not authenticated",
            status.HTTP_403_FORBIDDEN: "The user does not have the required permissions",
        },
    )
    @authz_permissions(
        [
            permissions.VIEW_LIBRARY_TEAM.identifier,
            permissions.COURSES_VIEW_COURSE_TEAM.identifier,
        ]
    )
    def get(self, request: HttpRequest) -> Response:
        """Retrieve all user role assignments."""
        serializer = ListAssignmentsQuerySerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        query_params = serializer.validated_data

        user_role_assignments: list[UserAssignmentData | SuperAdminAssignmentData] = []

        # Retrieve superadmin assignments (django staff or superuser users), as they always have access to everything
        user_role_assignments += get_superadmin_assignments()

        users_with_assignments = api.get_visible_role_assignments_for_user(
            orgs=query_params.get("orgs"),
            scopes=query_params.get("scopes"),
            roles=query_params.get("roles"),
            allowed_for_user_external_key=request.user.username,
        )

        # Unpack list of UserAssignments to a list of UserAssignmentData
        for uwa in users_with_assignments:
            user_role_assignments += [
                UserAssignmentData(
                    user=uwa.user, subject=assignment.subject, roles=assignment.roles, scope=assignment.scope
                )
                for assignment in uwa.assignments
            ]

        assignments = TeamMemberUserAssignmentSerializer(user_role_assignments, many=True).data
        for backend in self.filter_backends:
            assignments = backend().filter_queryset(request, assignments, self)

        # Paginate
        paginator = self.pagination_class()
        paginated_response_data = paginator.paginate_queryset(assignments, request)
        return paginator.get_paginated_response(paginated_response_data)
