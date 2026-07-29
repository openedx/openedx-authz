"""
REST API views built for the Admin Console.

These views operate on Authorization's own data (roles, permissions, assignments,
scopes), but each is shaped around one specific Admin Console screen rather than being
a reusable, consumer-agnostic operation. See ``docs/decisions/0016-rest-api-domain-ownership-boundary.rst``.
"""

import logging
import operator
from functools import reduce

import edx_api_doc_tools as apidocs
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
    PlatformGlobData,
    UserAssignmentData,
)
from openedx_authz.api.users import (
    get_scopes_for_user_and_permission,
    get_superadmin_assignments,
    get_visible_role_assignments_for_user,
    get_visible_user_role_assignments_filtered_by_current_user,
)
from openedx_authz.constants import permissions
from openedx_authz.models.scopes import get_content_library_model, get_course_overview_model
from openedx_authz.rest_api.data import ScopesQuerySetFields, ScopesTypeField
from openedx_authz.rest_api.decorators import authz_permissions, view_auth_classes
from openedx_authz.rest_api.v1.admin_console.filters import (
    TeamMemberAssignmentsOrderingFilter,
    TeamMemberOrderingFilter,
    TeamMemberSearchFilter,
    UserAssignmentsOrderingFilter,
    UserAssignmentsSearchFilter,
)
from openedx_authz.rest_api.v1.paginators import AuthZAPIViewPagination
from openedx_authz.rest_api.v1.permissions import AnyScopePermission
from openedx_authz.rest_api.v1.serializers import (
    ListAssignmentsQuerySerializer,
    ListScopesQuerySerializer,
    ListTeamMemberAssignmentsQuerySerializer,
    ListTeamMembersSerializer,
    ScopeSerializer,
    TeamMemberAssignmentSerializer,
    TeamMemberSerializer,
    TeamMemberUserAssignmentSerializer,
)

logger = logging.getLogger(__name__)

ContentLibrary = get_content_library_model()
CourseOverview = get_course_overview_model()


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
        org_glob_cls: type,
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
            org_glob_cls: The org-level glob class (e.g., OrgCourseOverviewGlobData).
            get_permission: Callable that returns the permission for a scope class.
            queryset_builder: Callable that builds the filtered queryset (e.g., _get_courses_queryset).
            extract_ids: Callable that extracts specific IDs from non-glob scopes.
            search: Optional search term to filter by display name.
            org: Optional org short_name to filter by.

        Returns:
            QuerySet: The filtered queryset projected to the unified scope shape.
        """
        allowed_scopes = get_scopes_for_user_and_permission(username, get_permission(scope_cls).identifier)

        has_platform_access = any(isinstance(s, PlatformGlobData) for s in allowed_scopes)
        if has_platform_access:
            return queryset_builder(search=search, orgs=orgs)

        specific_scopes = [s for s in allowed_scopes if not s.IS_GLOB]
        allowed_ids = extract_ids(specific_scopes)
        allowed_orgs = {s.org for s in allowed_scopes if isinstance(s, org_glob_cls)}
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
                org_glob_cls=OrgCourseOverviewGlobData,
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
                org_glob_cls=OrgContentLibraryGlobData,
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

        users_with_assignments = get_visible_role_assignments_for_user(
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

        user_role_assignments: list[api.RoleAssignmentData | api.SuperAdminAssignmentData] = []

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

        user_role_assignments: list[UserAssignmentData] = []

        users_with_assignments = get_visible_role_assignments_for_user(
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
