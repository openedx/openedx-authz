"""
Unit tests for the Open edX AuthZ REST API views.

This test suite validates the functionality of the authorization REST API endpoints,
including permission validation, user-role management, and role listing capabilities.
"""

from unittest.mock import patch
from urllib.parse import urlencode

from ddt import data, ddt, unpack
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from openedx_authz import api
from openedx_authz.api.data import (
    CourseOverviewData,
    OrgContentLibraryGlobData,
    OrgCourseOverviewGlobData,
    PlatformContentLibraryGlobData,
    PlatformCourseOverviewGlobData,
)
from openedx_authz.api.users import assign_role_to_user_in_scope
from openedx_authz.constants import permissions, roles
from openedx_authz.rest_api.data import RoleOperationError, RoleOperationStatus
from openedx_authz.rest_api.v1.permissions import AnyScopePermission, DynamicScopePermission
from openedx_authz.rest_api.v1.views import UserValidationAPIView
from openedx_authz.tests.api.test_roles import BaseRolesTestCase

User = get_user_model()

COURSE_SCOPE_ORG1 = "course-v1:Org1+COURSE1+2024"
COURSE_ORG1_GLOB = OrgCourseOverviewGlobData.build_external_key(CourseOverviewData(external_key=COURSE_SCOPE_ORG1).org)
PLATFORM_COURSE_GLOB = PlatformCourseOverviewGlobData.build_external_key()
LIB_SCOPE_ORG1 = "lib:Org1:LIB1"
LIB_ORG1_GLOB = OrgContentLibraryGlobData.build_external_key("Org1")
PLATFORM_LIBRARY_GLOB = PlatformContentLibraryGlobData.build_external_key()


class ViewTestMixin(BaseRolesTestCase):
    """Mixin providing common test utilities for view tests."""

    @classmethod
    def _assign_roles_to_users(cls, assignments: list[dict] | None = None):
        """Helper method to assign roles to multiple users.

        This method can be used to assign a role to a single user or multiple users
        in a specific scope. It can also handle batch assignments.

        Args:
            assignments (list of dict): List of assignment dictionaries, each containing:
                - subject_name (str): External key of the user (e.g., 'john_doe').
                - role_name (str): External key of the role to assign (e.g., 'library_admin').
                - scope_name (str): External key of the scope in which to assign the role (e.g., 'lib:Org1:math_101').
        """
        for assignment in assignments or []:
            assign_role_to_user_in_scope(
                user_external_key=assignment["subject_name"],
                role_external_key=assignment["role_name"],
                scope_external_key=assignment["scope_name"],
            )

    @classmethod
    def setUpClass(cls):
        """Set up test class with custom role assignments."""
        super().setUpClass()
        assignments = [
            # Assign roles to admin users
            {
                "subject_name": "admin_1",
                "role_name": roles.LIBRARY_ADMIN.external_key,
                "scope_name": "lib:Org1:LIB1",
            },
            {
                "subject_name": "admin_2",
                "role_name": roles.LIBRARY_USER.external_key,
                "scope_name": "lib:Org2:LIB2",
            },
            {
                "subject_name": "admin_3",
                "role_name": roles.LIBRARY_ADMIN.external_key,
                "scope_name": "lib:Org3:LIB3",
            },
            # Assign roles to regular users
            {
                "subject_name": "regular_1",
                "role_name": roles.LIBRARY_USER.external_key,
                "scope_name": "lib:Org1:LIB1",
            },
            {
                "subject_name": "regular_2",
                "role_name": roles.LIBRARY_USER.external_key,
                "scope_name": "lib:Org1:LIB1",
            },
            {
                "subject_name": "regular_3",
                "role_name": roles.LIBRARY_USER.external_key,
                "scope_name": "lib:Org2:LIB2",
            },
            {
                "subject_name": "regular_4",
                "role_name": roles.LIBRARY_USER.external_key,
                "scope_name": "lib:Org2:LIB2",
            },
            {
                "subject_name": "regular_5",
                "role_name": roles.LIBRARY_ADMIN.external_key,
                "scope_name": "lib:Org3:LIB3",
            },
            {
                "subject_name": "regular_6",
                "role_name": roles.LIBRARY_AUTHOR.external_key,
                "scope_name": "lib:Org3:LIB3",
            },
            {
                "subject_name": "regular_7",
                "role_name": "library_contributor",
                "scope_name": "lib:Org3:LIB3",
            },
            {
                "subject_name": "regular_8",
                "role_name": roles.LIBRARY_USER.external_key,
                "scope_name": "lib:Org3:LIB3",
            },
        ]
        cls._assign_roles_to_users(assignments=assignments)

    @classmethod
    def create_regular_users(cls, quantity: int):
        """Create regular users."""
        for i in range(1, quantity + 1):
            User.objects.get_or_create(username=f"regular_{i}", defaults={"email": f"regular_{i}@example.com"})

    @classmethod
    def create_admin_users(cls, quantity: int):
        """Create admin users."""
        for i in range(1, quantity + 1):
            user, created = User.objects.get_or_create(
                username=f"admin_{i}", defaults={"email": f"admin_{i}@example.com"}
            )
            if created:
                user.is_superuser = True
                user.is_staff = True
                user.save()

    @classmethod
    def create_course_users(cls):
        """Create course users (plain, non-staff)."""
        users = ["course_admin", "course_editor", "course_auditor", "course_admin_org", "course_admin_platform"]
        for username in users:
            User.objects.get_or_create(username=username, defaults={"email": f"{username}@example.com"})

    @classmethod
    def create_library_users(cls):
        """Create library users (plain, non-staff)."""
        users = ["library_admin", "library_admin_org", "library_admin_platform"]
        for username in users:
            User.objects.get_or_create(username=username, defaults={"email": f"{username}@example.com"})

    @classmethod
    def setUpTestData(cls):
        """Set up test fixtures once for the entire test class."""
        super().setUpTestData()
        cls.create_admin_users(quantity=3)
        cls.create_regular_users(quantity=10)
        cls.create_course_users()
        cls.create_library_users()

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.client = APIClient()
        self.admin_user = User.objects.get(username="admin_1")
        self.regular_user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=self.admin_user)


@ddt
class TestPermissionValidationMeView(ViewTestMixin):
    """Test suite for PermissionValidationMeView."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.url = reverse("openedx_authz:permission-validation-me")

    @data(
        # Single permission - allowed
        ([{"action": permissions.VIEW_LIBRARY.identifier, "scope": "lib:Org1:LIB1"}], [True]),
        # Single permission - denied (scope not assigned to user)
        ([{"action": permissions.VIEW_LIBRARY.identifier, "scope": "lib:Org2:LIB2"}], [False]),
        # Single permission - denied (action not assigned to user)
        ([{"action": "content_libraries.edit_library", "scope": "lib:Org1:LIB1"}], [False]),
        # Multiple permissions - mixed results
        (
            [
                {"action": permissions.VIEW_LIBRARY.identifier, "scope": "lib:Org1:LIB1"},
                {"action": permissions.VIEW_LIBRARY.identifier, "scope": "lib:Org2:LIB2"},
                {"action": "content_libraries.edit_library", "scope": "lib:Org1:LIB1"},
            ],
            [True, False, False],
        ),
    )
    @unpack
    def test_permission_validation_success(self, request_data: list[dict], permission_map: list[bool]):
        """Test successful permission validation requests.

        Expected result:
            - Returns 200 OK status
            - Returns correct permission validation results
        """
        self.client.force_authenticate(user=self.regular_user)
        expected_response = request_data.copy()
        for idx, perm in enumerate(permission_map):
            expected_response[idx]["allowed"] = perm

        response = self.client.post(self.url, data=request_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, expected_response)

    @data(
        ("lib:AnyOrg1:ANYLIB1", True),
        ("lib:AnyOrg2:ANYLIB2", True),
        ("lib:AnyOrg3:ANYLIB3", True),
        ("global:AnyScope1", False),
    )
    @unpack
    def test_permission_validation_staff_superuser_access(self, scope: str, expected_result: bool):
        """Test that staff/superuser users have guaranteed permissions for ContentLibrary scopes.

        Test cases:
            - ContentLibrary scopes (lib:*): Staff/superuser automatically allowed
            - Generic scopes (global:*): No automatic access granted

        Expected result:
            - Returns 200 OK status
            - For library scopes: All permissions are allowed (True)
            - For non-library scopes: Permissions follow normal authorization (False)
        """
        self.client.force_authenticate(user=self.admin_user)
        request_data = [{"action": perm.identifier, "scope": scope} for perm in roles.LIBRARY_ADMIN_PERMISSIONS]
        expected_response = request_data.copy()
        for item in expected_response:
            item["allowed"] = expected_result

        response = self.client.post(self.url, data=request_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, expected_response)

    @data(
        # Single permission
        [{"scope": "lib:Org1:LIB1"}],
        [{"action": "edit_library", "scope": ""}],
        [{"action": "edit_library", "scope": "s" * 256}],
        [{"action": "", "scope": "lib:Org1:LIB1"}],
        [{"action": "a" * 256, "scope": "lib:Org1:LIB1"}],
        # Multiple permissions
        [{}, {}],
        [{}, {"action": "edit_library", "scope": "lib:Org1:LIB1"}],
        [{"action": "edit_library", "scope": "lib:Org1:LIB1"}, {}],
        [
            {"action": "edit_library", "scope": "lib:Org1:LIB1"},
            {"action": "", "scope": "lib:Org1:LIB1"},
        ],
        [
            {"action": "edit_library", "scope": "lib:Org1:LIB1"},
            {"action": "edit_library", "scope": ""},
        ],
        [
            {"action": "edit_library", "scope": "lib:Org1:LIB1"},
            {"scope": "lib:Org1:LIB1"},
        ],
    )
    def test_permission_validation_invalid_data(self, invalid_data: list[dict]):
        """Test permission validation with invalid request data.

        Expected result:
            - Returns 400 BAD REQUEST status
        """
        response = self.client.post(self.url, data=invalid_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @data(
        # Single action the user has in some scope (LIBRARY_USER on lib:Org1:LIB1) - allowed
        ([{"action": permissions.VIEW_LIBRARY.identifier}], [True]),
        # Single action the user has in no scope - denied
        ([{"action": permissions.MANAGE_LIBRARY_TEAM.identifier}], [False]),
        # Multiple actions - mixed results
        (
            [
                {"action": permissions.VIEW_LIBRARY.identifier},
                {"action": permissions.MANAGE_LIBRARY_TEAM.identifier},
                {"action": permissions.COURSES_MANAGE_COURSE_TEAM.identifier},
            ],
            [True, False, False],
        ),
    )
    @unpack
    def test_permission_validation_any_scope_success(self, request_data: list[dict], permission_map: list[bool]):
        """Test permission validation without a scope (any-scope check).

        When the scope is omitted, the permission is validated across any scope: the user
        is allowed if they hold the permission in at least one scope.

        Expected result:
            - Returns 200 OK status
            - Response omits the scope key and reports the any-scope result
        """
        self.client.force_authenticate(user=self.regular_user)
        expected_response = [
            {"action": perm["action"], "allowed": allowed}
            for perm, allowed in zip(request_data, permission_map)
        ]

        response = self.client.post(self.url, data=request_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, expected_response)

    def test_permission_validation_any_scope_staff_always_allowed(self):
        """Staff/superusers are allowed for any action when no scope is provided.

        Expected result:
            - Returns 200 OK status
            - Every action is allowed regardless of explicit assignments
        """
        self.client.force_authenticate(user=self.admin_user)
        request_data = [
            {"action": permissions.MANAGE_LIBRARY_TEAM.identifier},
            {"action": permissions.COURSES_MANAGE_COURSE_TEAM.identifier},
        ]
        expected_response = [{"action": perm["action"], "allowed": True} for perm in request_data]

        response = self.client.post(self.url, data=request_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, expected_response)

    def test_permission_validation_unauthenticated(self):
        """Test permission validation without authentication.

        Expected result:
            - Returns 401 UNAUTHORIZED status
        """
        action = "edit_library"
        scope = "lib:Org1:LIB1"
        self.client.force_authenticate(user=None)

        response = self.client.post(self.url, data=[{"action": action, "scope": scope}], format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @data(
        (
            Exception(),
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "An error occurred while validating permissions",
        ),
        (ValueError(), status.HTTP_400_BAD_REQUEST, "Invalid scope format"),
    )
    @unpack
    def test_permission_validation_exception_handling(self, exception: Exception, status_code: int, message: str):
        """Test permission validation exception handling for different error types.

        Expected result:
            - Generic Exception: Returns 500 INTERNAL SERVER ERROR with appropriate message
            - ValueError: Returns 400 BAD REQUEST with scope format error message
        """
        with patch.object(api, "is_user_allowed", side_effect=exception):
            response = self.client.post(
                self.url,
                data=[{"action": "edit_library", "scope": "lib:Org1:LIB1"}],
                format="json",
            )

            self.assertEqual(response.status_code, status_code)
            self.assertEqual(response.data, {"message": message})


@ddt
class TestRoleUserAPIView(ViewTestMixin):
    """Test suite for RoleUserAPIView."""

    _COURSE_ASSIGNMENTS = [
        {
            "subject_name": "course_admin",
            "role_name": roles.COURSE_ADMIN.external_key,
            "scope_name": COURSE_SCOPE_ORG1,
        },
        {
            "subject_name": "course_editor",
            "role_name": roles.COURSE_EDITOR.external_key,
            "scope_name": COURSE_SCOPE_ORG1,
        },
        {
            "subject_name": "course_auditor",
            "role_name": roles.COURSE_AUDITOR.external_key,
            "scope_name": COURSE_SCOPE_ORG1,
        },
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._assign_roles_to_users(assignments=cls._COURSE_ASSIGNMENTS)

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.client.force_authenticate(user=self.admin_user)
        self.url = reverse("openedx_authz:role-user-list")

    @data(
        # All users
        ({}, 3),
        # Search by username
        ({"search": "regular_1"}, 1),
        ({"search": "regular"}, 2),
        ({"search": "nonexistent"}, 0),
        # Search by email
        ({"search": "regular_1@example.com"}, 1),
        ({"search": "@example.com"}, 3),
        ({"search": "nonexistent@example.com"}, 0),
        # Search by single role
        ({"roles": roles.LIBRARY_ADMIN.external_key}, 1),
        ({"roles": roles.LIBRARY_AUTHOR.external_key}, 0),
        ({"roles": roles.LIBRARY_USER.external_key}, 2),
        # Search by multiple roles
        ({"roles": "library_admin,library_author"}, 1),
        ({"roles": "library_author,library_user"}, 2),
        ({"roles": "library_user,library_admin"}, 3),
        ({"roles": "library_admin,library_author,library_user"}, 3),
        # Search by role and username
        ({"search": "admin_1", "roles": roles.LIBRARY_ADMIN.external_key}, 1),
        ({"search": "regular_1", "roles": roles.LIBRARY_USER.external_key}, 1),
        ({"search": "regular_1", "roles": roles.LIBRARY_ADMIN.external_key}, 0),
        # Search by role and email
        ({"search": "admin_1@example.com", "roles": roles.LIBRARY_ADMIN.external_key}, 1),
        ({"search": "@example.com", "roles": roles.LIBRARY_ADMIN.external_key}, 1),
        ({"search": "@example.com", "roles": roles.LIBRARY_USER.external_key}, 2),
        ({"search": "regular_1@example.com", "roles": roles.LIBRARY_ADMIN.external_key}, 0),
    )
    @unpack
    def test_get_users_by_scope_success(self, query_params: dict, expected_count: int):
        """Test retrieving users with their role assignments in a scope.

        Expected result:
            - Returns 200 OK status
            - Returns correct user role assignments
        """
        query_params["scope"] = "lib:Org1:LIB1"

        response = self.client.get(self.url, query_params)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertIn("count", response.data)
        self.assertEqual(len(response.data["results"]), expected_count)
        self.assertEqual(response.data["count"], expected_count)

    @data(
        {},
        {"scope": ""},
        {"scope": "a" * 256},
        {"scope": "lib:Org1:LIB1", "sort_by": "invalid"},
        {"scope": "lib:Org1:LIB1", "sort_by": "name"},
        {"scope": "lib:Org1:LIB1", "order": "ascending"},
        {"scope": "lib:Org1:LIB1", "order": "descending"},
        {"scope": "lib:Org1:LIB1", "order": "up"},
        {"scope": "lib:Org1:LIB1", "order": "down"},
    )
    def test_get_users_by_scope_invalid_params(self, query_params: dict):
        """Test retrieving users with invalid query parameters.

        Test cases:
            - Missing scope parameter
            - Empty scope value
            - Scope exceeding max_length (255 chars)
            - Invalid sort_by values (not in: username, full_name, email)
            - Invalid order values (not in: asc, desc)

        Expected result:
            - Returns 400 BAD REQUEST status
        """
        response = self.client.get(self.url, query_params)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @data(
        # Unauthenticated
        (None, status.HTTP_401_UNAUTHORIZED),
        # Admin user
        ("admin_1", status.HTTP_200_OK),
        # Regular user with permission
        ("regular_1", status.HTTP_200_OK),
        # Regular user without permission
        ("regular_3", status.HTTP_403_FORBIDDEN),
    )
    @unpack
    def test_get_users_by_scope_permissions(self, username: str, status_code: int):
        """Test retrieving users in a role with different user permissions.

        Expected result:
            - Returns appropriate status code based on permissions
        """
        user = User.objects.filter(username=username).first()
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url, {"scope": "lib:Org1:LIB1"})

        self.assertEqual(response.status_code, status_code)

    # --- Course scope equivalents ---

    @data(
        # Unauthenticated
        (None, status.HTTP_401_UNAUTHORIZED),
        # Django superuser always passes
        ("admin_1", status.HTTP_200_OK),
        # course_admin has COURSES_MANAGE_COURSE_TEAM ⊇ COURSES_VIEW_COURSE_TEAM
        ("course_admin", status.HTTP_200_OK),
        # course_editor has COURSES_VIEW_COURSE_TEAM
        ("course_editor", status.HTTP_200_OK),
        # course_auditor has COURSES_VIEW_COURSE_TEAM
        ("course_auditor", status.HTTP_200_OK),
        # Library-only user has no course permission
        ("regular_1", status.HTTP_403_FORBIDDEN),
    )
    @unpack
    def test_get_users_by_scope_course_permissions(self, username: str, status_code: int):
        """Mirror of test_get_users_by_scope_permissions for course scopes.

        Expected result:
            - Returns appropriate status code based on course-scope permissions.
        """
        user = User.objects.filter(username=username).first()
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url, {"scope": COURSE_SCOPE_ORG1})

        self.assertEqual(response.status_code, status_code)

    @data(
        # With username -----------------------------
        # Single user - success (admin user)
        (["admin_1"], 1, 0),
        # Single user - success (regular user)
        (["regular_1"], 1, 0),
        # Multiple users - success (admin and regular users)
        (["admin_1", "regular_1", "regular_2"], 3, 0),
        # With email ---------------------------------
        # Single user - success (admin user)
        (["admin_1@example.com"], 1, 0),
        # Single user - success (regular user)
        (["regular_1@example.com"], 1, 0),
        # Multiple users - admin and regular users
        (
            ["admin_1@example.com", "regular_1@example.com", "regular_2@example.com"],
            3,
            0,
        ),
        # With username and email --------------------
        # All success
        (["admin_1", "regular_1@example.com", "regular_2@example.com"], 3, 0),
        # Mixed results (user not found)
        (
            [
                "admin_1",
                "regular_1@example.com",
                "nonexistent",
                "notexistent@example.com",
            ],
            2,
            2,
        ),
    )
    @unpack
    def test_add_users_to_role_success(self, users: list[str], expected_completed: int, expected_errors: int):
        """Test adding users to a role within a scope.

        Expected result:
            - Returns 207 MULTI-STATUS status
            - Returns appropriate completed and error counts
        """
        role = roles.LIBRARY_ADMIN.external_key
        request_data = {"role": role, "scope": "lib:Org1:LIB3", "users": users}

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.put(self.url, data=request_data, format="json")

            self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
            self.assertEqual(len(response.data["completed"]), expected_completed)
            self.assertEqual(len(response.data["errors"]), expected_errors)

    @data(
        # Single user - success (admin user)
        (["admin_2"], 0, 1),
        # Single user - success (regular user)
        (["regular_3"], 0, 1),
        # Multiple users - one user already has the role
        (["regular_1", "regular_2", "regular_3"], 2, 1),
        # Multiple users - all users already have the role
        (["admin_2", "regular_3", "regular_4"], 0, 3),
    )
    @unpack
    def test_add_users_to_role_already_has_role(self, users: list[str], expected_completed: int, expected_errors: int):
        """Test adding users to a role that already has the role."""
        role = roles.LIBRARY_USER.external_key
        scope = "lib:Org2:LIB2"
        request_data = {"role": role, "scope": scope, "users": users}

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.put(self.url, data=request_data, format="json")

            self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
            self.assertEqual(len(response.data["completed"]), expected_completed)
            self.assertEqual(len(response.data["errors"]), expected_errors)

    @patch.object(api, "assign_role_to_user_in_scope")
    def test_add_users_to_role_exception_handling(self, mock_assign_role_to_user_in_scope):
        """Test adding users to a role with exception handling."""
        request_data = {
            "role": roles.LIBRARY_ADMIN.external_key,
            "scope": "lib:Org1:LIB1",
            "users": ["regular_1"],
        }
        mock_assign_role_to_user_in_scope.side_effect = Exception()

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.put(self.url, data=request_data, format="json")

            self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
            self.assertEqual(len(response.data["completed"]), 0)
            self.assertEqual(len(response.data["errors"]), 1)
            self.assertEqual(response.data["errors"][0]["user_identifier"], "regular_1")
            self.assertEqual(
                response.data["errors"][0]["error"],
                RoleOperationError.ROLE_ASSIGNMENT_ERROR,
            )

    @data(
        {},
        {"role": roles.LIBRARY_ADMIN.external_key},
        {"scope": "lib:Org1:LIB1"},
        {"users": ["admin_1"]},
        {"role": roles.LIBRARY_ADMIN.external_key, "scope": "lib:Org1:LIB1"},
        {"scope": "lib:Org1:LIB1", "users": ["admin_1"]},
        {"users": ["admin_1", "regular_1"], "role": roles.LIBRARY_ADMIN.external_key},
        {"role": roles.LIBRARY_ADMIN.external_key, "scope": "lib:Org1:LIB1", "users": []},
        {"role": "", "scope": "lib:Org1:LIB1", "users": ["admin_1"]},
        {"role": roles.LIBRARY_ADMIN.external_key, "scope": "", "users": ["admin_1"]},
    )
    def test_add_users_to_role_invalid_data(self, request_data: dict):
        """Test adding users with invalid request data.

        Expected result:
            - Returns 400 BAD REQUEST status
        """
        with patch.object(DynamicScopePermission, "has_permission", return_value=True):
            response = self.client.put(self.url, data=request_data, format="json")

            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @data(
        # Single scope in 'scopes' list - one user, success
        (["admin_1"], ["lib:Org1:LIB3"], 1, 0),
        # Single scope in 'scopes' list - multiple users, all success
        (["admin_1", "regular_1"], ["lib:Org1:LIB3"], 2, 0),
        # Two scopes - one user, success in both
        (["admin_1"], ["lib:Org1:LIB3", "lib:Org2:LIB4"], 2, 0),
        # Two scopes - two users, all succeed (2 scopes * 2 users = 4 completed)
        (["admin_1", "regular_1"], ["lib:Org1:LIB3", "lib:Org2:LIB4"], 4, 0),
        # Three scopes - one user, success in all
        (["admin_1"], ["lib:Org1:LIB3", "lib:Org2:LIB4", "lib:Org3:LIB5"], 3, 0),
    )
    @unpack
    def test_add_users_to_role_multi_scope_success(
        self,
        users: list[str],
        scopes: list[str],
        expected_completed: int,
        expected_errors: int,
    ):
        """Test adding users to a role using the new 'scopes' list field.

        Expected result:
            - Returns 207 MULTI-STATUS
            - Completed count equals len(users) * len(scopes) when all succeed
            - Each completed entry contains a 'scope' field
        """
        role = roles.LIBRARY_ADMIN.external_key
        request_data = {"role": role, "scopes": scopes, "users": users}

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.put(self.url, data=request_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
        self.assertEqual(len(response.data["completed"]), expected_completed)
        self.assertEqual(len(response.data["errors"]), expected_errors)
        for entry in response.data["completed"]:
            self.assertIn("scope", entry)
            self.assertIn(entry["scope"], scopes)

    def test_add_users_to_role_backward_compat_response_includes_scope(self):
        """Test that the old single-'scope' payload still works and response includes scope.

        Expected result:
            - Returns 207 MULTI-STATUS
            - Each completed entry contains a 'scope' field matching the requested scope
        """
        scope = "lib:Org1:LIB3"
        request_data = {
            "role": roles.LIBRARY_ADMIN.external_key,
            "scope": scope,
            "users": ["admin_1", "regular_1"],
        }

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.put(self.url, data=request_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
        self.assertEqual(len(response.data["completed"]), 2)
        for entry in response.data["completed"]:
            self.assertIn("scope", entry)
            self.assertEqual(entry["scope"], scope)

    @data(
        # Both 'scope' and 'scopes' provided
        {
            "role": roles.LIBRARY_ADMIN.external_key,
            "scope": "lib:Org1:LIB1",
            "scopes": ["lib:Org2:LIB2"],
            "users": ["admin_1"],
        },
        # 'scopes' as empty list
        {
            "role": roles.LIBRARY_ADMIN.external_key,
            "scopes": [],
            "users": ["admin_1"],
        },
    )
    def test_add_users_to_role_invalid_scopes_field(self, request_data: dict):
        """Test that invalid combinations of scope/scopes fields return 400.

        Expected result:
            - Returns 400 BAD REQUEST status
        """
        with patch.object(DynamicScopePermission, "has_permission", return_value=True):
            response = self.client.put(self.url, data=request_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @data(
        # Unauthenticated
        (None, status.HTTP_401_UNAUTHORIZED),
        # Admin user
        ("admin_3", status.HTTP_207_MULTI_STATUS),
        # Regular user with permission
        ("regular_5", status.HTTP_207_MULTI_STATUS),
        # Regular user without permission
        ("regular_3", status.HTTP_403_FORBIDDEN),
    )
    @unpack
    def test_add_users_to_role_permissions(self, username: str, status_code: int):
        """Test adding users to role with different permission scenarios.

        Expected result:
            - Returns appropriate status code based on permissions
        """
        request_data = {
            "role": roles.LIBRARY_ADMIN.external_key,
            "scope": "lib:Org3:LIB3",
            "users": ["regular_2"],
        }
        user = User.objects.filter(username=username).first()
        self.client.force_authenticate(user=user)

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.put(self.url, data=request_data, format="json")

            self.assertEqual(response.status_code, status_code)

    # --- Course scope equivalents ---

    @data(
        # Unauthenticated
        (None, status.HTTP_401_UNAUTHORIZED),
        # Django superuser always passes
        ("admin_1", status.HTTP_207_MULTI_STATUS),
        # course_admin has COURSES_MANAGE_COURSE_TEAM
        ("course_admin", status.HTTP_207_MULTI_STATUS),
        # course_editor has COURSES_VIEW_COURSE_TEAM only — cannot manage team
        ("course_editor", status.HTTP_403_FORBIDDEN),
        # course_auditor has COURSES_VIEW_COURSE_TEAM only — cannot manage team
        ("course_auditor", status.HTTP_403_FORBIDDEN),
        # Library-only user has no course permission
        ("regular_1", status.HTTP_403_FORBIDDEN),
    )
    @unpack
    def test_add_users_to_role_course_permissions(self, username: str, status_code: int):
        """Mirror of test_add_users_to_role_permissions for course scopes.

        Expected result:
            - Returns appropriate status code based on course-scope permissions.
        """
        request_data = {
            "role": roles.COURSE_ADMIN.external_key,
            "scope": COURSE_SCOPE_ORG1,
            "users": ["regular_2"],
        }
        user = User.objects.filter(username=username).first()
        self.client.force_authenticate(user=user)

        with patch.object(api.CourseOverviewData, "exists", return_value=True):
            response = self.client.put(self.url, data=request_data, format="json")

        self.assertEqual(response.status_code, status_code)

    @data(
        # With username -----------------------------
        # Single user - success (admin user)
        (["admin_2"], 1, 0),
        # Single user - success (regular user)
        (["regular_3"], 1, 0),
        # Multiple users - all success (admin and regular users)
        (["admin_2", "regular_3", "regular_4"], 3, 0),
        # With email --------------------------------
        # Single user - success (admin user)
        (["admin_2@example.com"], 1, 0),
        # Single user - success (regular user)
        (["regular_3@example.com"], 1, 0),
        # Multiple users - all success (admin and regular users)
        (
            ["admin_2@example.com", "regular_3@example.com", "regular_4@example.com"],
            3,
            0,
        ),
        # With username and email -------------------
        # All success
        (["admin_2", "regular_3@example.com", "regular_4@example.com"], 3, 0),
        # Mixed results (user not found)
        (
            [
                "admin_2",
                "regular_3@example.com",
                "nonexistent",
                "notexistent@example.com",
            ],
            2,
            2,
        ),
    )
    @unpack
    def test_remove_users_from_role_success(self, users: list[str], expected_completed: int, expected_errors: int):
        """Test removing users from a role within a scope.

        Expected result:
            - Returns 207 MULTI-STATUS status
            - Returns appropriate completed and error counts
        """
        query_params = {
            "role": roles.LIBRARY_USER.external_key,
            "scope": "lib:Org2:LIB2",
            "users": ",".join(users),
        }

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.delete(f"{self.url}?{urlencode(query_params)}")

            self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
            self.assertEqual(len(response.data["completed"]), expected_completed)
            self.assertEqual(len(response.data["errors"]), expected_errors)

    @patch.object(api, "unassign_role_from_user")
    def test_remove_users_from_role_exception_handling(self, mock_unassign_role_from_user):
        """Test removing users from a role with exception handling."""
        query_params = {
            "role": roles.LIBRARY_ADMIN.external_key,
            "scope": "lib:Org1:LIB1",
            "users": "regular_1,regular_2,regular_3",
        }
        mock_unassign_role_from_user.side_effect = [True, False, Exception()]

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.delete(f"{self.url}?{urlencode(query_params)}")
            self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
            self.assertEqual(len(response.data["completed"]), 1)
            self.assertEqual(len(response.data["errors"]), 2)
            self.assertEqual(response.data["completed"][0]["user_identifier"], "regular_1")
            self.assertEqual(
                response.data["completed"][0]["status"],
                RoleOperationStatus.ROLE_REMOVED,
            )
            self.assertEqual(response.data["errors"][0]["user_identifier"], "regular_2")
            self.assertEqual(
                response.data["errors"][0]["error"],
                RoleOperationError.USER_DOES_NOT_HAVE_ROLE,
            )
            self.assertEqual(response.data["errors"][1]["user_identifier"], "regular_3")
            self.assertEqual(
                response.data["errors"][1]["error"],
                RoleOperationError.ROLE_REMOVAL_ERROR,
            )

    @data(
        {},
        {"role": roles.LIBRARY_ADMIN.external_key},
        {"scope": "lib:Org1:LIB1"},
        {"users": "admin_1"},
        {"role": roles.LIBRARY_ADMIN.external_key, "scope": "lib:Org1:LIB1"},
        {"scope": "lib:Org1:LIB1", "users": "admin_1"},
        {"users": "admin_1,regular_1", "role": roles.LIBRARY_ADMIN.external_key},
        {"role": roles.LIBRARY_ADMIN.external_key, "scope": "lib:Org1:LIB1", "users": ""},
        {"role": "", "scope": "lib:Org1:LIB1", "users": "admin_1"},
        {"role": roles.LIBRARY_ADMIN.external_key, "scope": "", "users": "admin_1"},
    )
    def test_remove_users_from_role_invalid_params(self, query_params: dict):
        """Test removing users with invalid query parameters.

        Expected result:
            - Returns 400 BAD REQUEST status
        """
        response = self.client.delete(f"{self.url}?{urlencode(query_params)}")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @data(
        # Unauthenticated
        (None, status.HTTP_401_UNAUTHORIZED),
        # Admin user
        ("admin_3", status.HTTP_207_MULTI_STATUS),
        # Regular user with permission
        ("regular_5", status.HTTP_207_MULTI_STATUS),
        # Regular user without permission
        ("regular_3", status.HTTP_403_FORBIDDEN),
    )
    @unpack
    def test_remove_users_from_role_permissions(self, username: str, status_code: int):
        """Test removing users from role with different permission scenarios.

        Expected result:
            - Returns appropriate status code based on permissions
        """
        query_params = {
            "role": roles.LIBRARY_ADMIN.external_key,
            "scope": "lib:Org3:LIB3",
            "users": "user1,user2",
        }
        user = User.objects.filter(username=username).first()
        self.client.force_authenticate(user=user)

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.delete(f"{self.url}?{urlencode(query_params)}")

            self.assertEqual(response.status_code, status_code)

    # --- Course scope equivalents ---

    @data(
        # Unauthenticated
        (None, status.HTTP_401_UNAUTHORIZED),
        # Django superuser always passes
        ("admin_1", status.HTTP_207_MULTI_STATUS),
        # course_admin has COURSES_MANAGE_COURSE_TEAM
        ("course_admin", status.HTTP_207_MULTI_STATUS),
        # course_editor has COURSES_VIEW_COURSE_TEAM only — cannot manage team
        ("course_editor", status.HTTP_403_FORBIDDEN),
        # course_auditor has COURSES_VIEW_COURSE_TEAM only — cannot manage team
        ("course_auditor", status.HTTP_403_FORBIDDEN),
        # Library-only user has no course permission
        ("regular_1", status.HTTP_403_FORBIDDEN),
    )
    @unpack
    def test_remove_users_from_role_course_permissions(self, username: str, status_code: int):
        """Mirror of test_remove_users_from_role_permissions for course scopes.

        Expected result:
            - Returns appropriate status code based on course-scope permissions.
        """
        query_params = {
            "role": roles.COURSE_ADMIN.external_key,
            "scope": COURSE_SCOPE_ORG1,
            "users": "regular_2",
        }
        user = User.objects.filter(username=username).first()
        self.client.force_authenticate(user=user)

        with patch.object(api.CourseOverviewData, "exists", return_value=True):
            response = self.client.delete(f"{self.url}?{urlencode(query_params)}")

        self.assertEqual(response.status_code, status_code)


@ddt
class TestRoleUserAPIViewScopeStringValidation(ViewTestMixin):
    """API tests for scope string validation on role assignment and removal (PUT/DELETE).

    These mirror security rules enforced by ``ScopeData(external_key=...)``: organization-level
    globs must use ``lib:ORG:*`` or ``course-v1:ORG+*``. Malicious patterns must be rejected
    before any assignment runs.
    """

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.client.force_authenticate(user=self.admin_user)
        self.url = reverse("openedx_authz:role-user-list")

    @data(
        # Bare global wildcard — not accepted via the API
        "*",
        # Course: globs only after full org segment (ORG+*), not course-v1:ORG* or mid-key globs
        "course-v1:OpenedX*",
        "course-v1:OpenedX**",
        "course-v1:c*",
        "course-v1:Open*",
        "course-v1:OpenedX+C*",
        "course-v1:OpenedX+CS101+*",
        "course-v1:OpenedX+CS101*",
        # Library: org-level glob is lib:ORG:* — not slug-level or stray *
        "lib:Org1:LIB*",
        "lib:DemoX*",
        "lib:DemoX:*:*",
        "lib:DemoX:slug*",
        # Wrong namespace or unparsable external keys
        "other:OpenedX+*",
        "unknown:DemoX:*",
        "not-a-valid-external-key",
        # Attempts to pass namespaced keys or Casbin-style keys as the external scope
        "course-v1^course-v1:OpenedX+*",
        "lib^lib:DemoX:*",
        "course-v1^course-v1:OpenedX*",
    )
    def test_put_rejects_malformed_or_overbroad_scope_strings(self, invalid_scope: str):
        """PUT must return 400 when the scope is not a valid concrete key or org-level glob."""
        request_data = {
            "role": roles.LIBRARY_ADMIN.external_key,
            "scope": invalid_scope,
            "users": ["regular_1"],
        }

        response = self.client.put(self.url, data=request_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @data(
        # Bare global wildcard — not accepted via the API
        "*",
        "course-v1:OpenedX*",
        "course-v1:OpenedX+CS101+*",
        "lib:DemoX*",
        "unknown:DemoX:*",
        "course-v1^course-v1:OpenedX+*",
    )
    def test_delete_rejects_malformed_or_overbroad_scope_strings(self, invalid_scope: str):
        """DELETE must return 400 for the same invalid scope strings as PUT."""
        query_params = {
            "role": roles.LIBRARY_ADMIN.external_key,
            "scope": invalid_scope,
            "users": "regular_1",
        }

        response = self.client.delete(f"{self.url}?{urlencode(query_params)}")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @data(
        # Empty org segment after validation (must not assign at "all orgs")
        "lib::*",
        "course-v1:+*",
        # Valid shape but organization is not in the system
        "lib:NonexistentOrgZ99:*",
        "course-v1:NonexistentOrgZ99+*",
    )
    def test_put_rejects_scope_that_does_not_exist(self, scope: str):
        """Well-formed keys that do not resolve to an existing org/course must return 400."""
        request_data = {
            "role": roles.LIBRARY_ADMIN.external_key,
            "scope": scope,
            "users": ["regular_1"],
        }

        response = self.client.put(self.url, data=request_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("scope", response.data)
        self.assertIn("invalid", [error.code for error in response.data["scope"]])

    @patch.object(api, "assign_role_to_user_in_scope", return_value=True)
    @patch.object(api.OrgContentLibraryGlobData, "exists", return_value=True)
    def test_put_accepts_valid_library_org_glob_scope(self, _mock_exists, _mock_assign):
        """Valid library org glob passes serializer validation and reaches assignment."""
        request_data = {
            "role": roles.LIBRARY_ADMIN.external_key,
            "scope": "lib:Org1:*",
            "users": ["regular_1"],
        }

        response = self.client.put(self.url, data=request_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
        self.assertEqual(len(response.data["completed"]), 1)

    @patch.object(api, "assign_role_to_user_in_scope", return_value=True)
    @patch.object(api.OrgCourseOverviewGlobData, "exists", return_value=True)
    def test_put_accepts_valid_course_org_glob_scope(self, _mock_exists, _mock_assign):
        """Valid course org glob (course-v1:ORG+*) passes validation for a course role."""
        request_data = {
            "role": roles.COURSE_STAFF.external_key,
            "scope": "course-v1:OpenedX+*",
            "users": ["regular_1"],
        }

        response = self.client.put(self.url, data=request_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
        self.assertEqual(len(response.data["completed"]), 1)

    @patch.object(api, "assign_role_to_user_in_scope", return_value=True)
    @patch.object(api.CourseOverviewData, "exists", return_value=True)
    def test_put_accepts_valid_full_course_key_scope(self, _mock_exists, _mock_assign):
        """A full course run key is accepted for a course role when the course exists."""
        request_data = {
            "role": roles.COURSE_STAFF.external_key,
            "scope": "course-v1:OpenedX+DemoCourse+2026_T1",
            "users": ["regular_1"],
        }

        response = self.client.put(self.url, data=request_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
        self.assertEqual(len(response.data["completed"]), 1)


@ddt
class TestRoleListView(ViewTestMixin):
    """Test suite for RoleListView."""

    _COURSE_ASSIGNMENTS = [
        {
            "subject_name": "course_admin",
            "role_name": roles.COURSE_ADMIN.external_key,
            "scope_name": COURSE_SCOPE_ORG1,
        },
        {
            "subject_name": "course_editor",
            "role_name": roles.COURSE_EDITOR.external_key,
            "scope_name": COURSE_SCOPE_ORG1,
        },
        {
            "subject_name": "course_auditor",
            "role_name": roles.COURSE_AUDITOR.external_key,
            "scope_name": COURSE_SCOPE_ORG1,
        },
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._assign_roles_to_users(assignments=cls._COURSE_ASSIGNMENTS)

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.client.force_authenticate(user=self.admin_user)
        self.url = reverse("openedx_authz:role-list")

    def test_get_roles_success(self):
        """Test retrieving role definitions and their permissions.

        Expected result:
            - Returns 200 OK status
            - Returns correct role definitions with permissions and user counts
        """
        response = self.client.get(self.url, {"scope": "lib:Org1:LIB1"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertIn("count", response.data)
        self.assertEqual(len(response.data["results"]), response.data["count"])
        self.assertEqual(len(response.data["results"]), 4)

    @patch.object(api, "get_role_definitions_in_scope")
    def test_get_roles_empty_result(self, mock_get_roles):
        """Test retrieving roles when none exist in scope.

        Expected result:
            - Returns 200 OK status
            - Returns empty results list
        """
        mock_get_roles.return_value = []

        response = self.client.get(self.url, {"scope": "lib:Org1:LIB1"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertIn("count", response.data)
        self.assertEqual(response.data["count"], 0)
        self.assertEqual(len(response.data["results"]), 0)

    @data(
        {},
        {"custom_param": "custom_value"},
        {"custom_param": "a" * 256, "another_param": "custom_value"},
    )
    def test_get_roles_scope_is_missing(self, query_params: dict):
        """Test retrieving roles with scope is missing.

        Expected result:
            - Returns 400 BAD REQUEST status
        """
        response = self.client.get(self.url, query_params)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("required", [error.code for error in response.data["scope"]])

    @data(
        ({"scope": ""}, "blank"),
        ({"scope": "a" * 256}, "max_length"),
        ({"scope": "invalid"}, "invalid"),
        ({"scope": "*"}, "invalid"),
    )
    @unpack
    def test_get_roles_scope_is_invalid(self, query_params: dict, error_code: str):
        """Test retrieving roles with invalid scope.

        Expected result:
            - Returns 400 BAD REQUEST status
        """
        response = self.client.get(self.url, query_params)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn(error_code, [error.code for error in response.data["scope"]])

    @data(
        ({}, 4, False),
        ({"page": 1, "page_size": 2}, 2, True),
        ({"page": 2, "page_size": 2}, 2, False),
        ({"page": 1, "page_size": 4}, 4, False),
    )
    @unpack
    def test_get_roles_pagination(self, query_params: dict, expected_count: int, has_next: bool):
        """Test retrieving roles with pagination.

        Expected result:
            - Returns 200 OK status
            - Returns paginated results with correct page size
        """
        query_params["scope"] = "lib:Org1:LIB1"
        response = self.client.get(self.url, query_params)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertEqual(len(response.data["results"]), expected_count)
        self.assertIn("next", response.data)
        if has_next:
            self.assertIsNotNone(response.data["next"])
        else:
            self.assertIsNone(response.data["next"])

    @data(
        # Unauthenticated
        (None, status.HTTP_401_UNAUTHORIZED),
        # Admin user
        ("admin_1", status.HTTP_200_OK),
        # Library Admin user
        ("regular_5", status.HTTP_200_OK),
        # Library Author user
        ("regular_6", status.HTTP_200_OK),
        # Library Contributor user
        ("regular_7", status.HTTP_200_OK),
        # Library User user
        ("regular_8", status.HTTP_200_OK),
        # Regular user without permission
        ("regular_9", status.HTTP_403_FORBIDDEN),
        # Non existent user
        ("non_existent_user", status.HTTP_401_UNAUTHORIZED),
    )
    @unpack
    def test_get_roles_permissions(self, username: str, status_code: int):
        """Test retrieving roles with permissions.

        Expected result:
            - Returns 401 UNAUTHORIZED status if user is not authenticated
            - Returns 403 FORBIDDEN status if user does not have permission
            - Returns 200 OK status if user has permission with correct roles with permissions and user counts
        """
        user = User.objects.filter(username=username).first()
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url, {"scope": "lib:Org3:LIB3"})

        self.assertEqual(response.status_code, status_code)
        if status_code == status.HTTP_200_OK:
            self.assertIn("results", response.data)
            self.assertIn("count", response.data)

    # --- Course scope equivalents ---

    @data(
        # Unauthenticated
        (None, status.HTTP_401_UNAUTHORIZED),
        # Django superuser always passes
        ("admin_1", status.HTTP_200_OK),
        # course_admin has COURSES_MANAGE_COURSE_TEAM ⊇ COURSES_VIEW_COURSE_TEAM
        ("course_admin", status.HTTP_200_OK),
        # course_auditor has COURSES_VIEW_COURSE_TEAM
        ("course_auditor", status.HTTP_200_OK),
        # Library-only user has no course permission
        ("regular_9", status.HTTP_403_FORBIDDEN),
    )
    @unpack
    def test_get_roles_course_permissions(self, username: str, status_code: int):
        """Mirror of test_get_roles_permissions for course scopes.

        Expected result:
            - Returns appropriate status code based on course-scope permissions.
        """
        user = User.objects.filter(username=username).first()
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url, {"scope": COURSE_SCOPE_ORG1})

        self.assertEqual(response.status_code, status_code)


@ddt
class TestUserValidationAPIView(ViewTestMixin):
    """Test suite for UserValidationAPIView."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.url = reverse("openedx_authz:user-validation")

    @data(
        # All users valid - usernames
        (["admin_1", "regular_1"], ["admin_1", "regular_1"], []),
        # All users valid - emails
        (["admin_1@example.com", "regular_1@example.com"], ["admin_1@example.com", "regular_1@example.com"], []),
        # Mixed usernames and emails
        (["admin_1", "regular_1@example.com"], ["admin_1", "regular_1@example.com"], []),
        # Single user
        (["admin_1"], ["admin_1"], []),
    )
    @unpack
    def test_post_all_users_valid(self, input_users: list, expected_valid: list, expected_invalid: list):
        """Test user validation when all users are valid.

        Expected result:
            - Returns 200 OK status
            - All users are in valid_users list
            - invalid_users list is empty
            - Summary contains correct counts
        """
        self.client.force_authenticate(user=self.admin_user)
        request_data = {"users": input_users}
        response = self.client.post(self.url, data=request_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["valid_users"], expected_valid)
        self.assertEqual(response.data["invalid_users"], expected_invalid)
        self.assertEqual(response.data["summary"]["total"], len(input_users))
        self.assertEqual(response.data["summary"]["valid_count"], len(expected_valid))
        self.assertEqual(response.data["summary"]["invalid_count"], len(expected_invalid))

    @data(
        # Mix of valid and invalid users
        (["admin_1", "nonexistent_user"], ["admin_1"], ["nonexistent_user"]),
        # Mix of valid and invalid with emails
        (["admin_1@example.com", "fake@example.com"], ["admin_1@example.com"], ["fake@example.com"]),
        # Mix of usernames and emails with some invalid
        (
            ["admin_1", "fake@example.com", "regular_1@example.com"],
            ["admin_1", "regular_1@example.com"],
            ["fake@example.com"],
        ),
        # More complex mix
        (
            ["admin_1", "nonexistent1", "regular_1@example.com", "nonexistent2"],
            ["admin_1", "regular_1@example.com"],
            ["nonexistent1", "nonexistent2"],
        ),
    )
    @unpack
    def test_post_mixed_valid_invalid_users(self, input_users: list, expected_valid: list, expected_invalid: list):
        """Test user validation when some users are valid and others are invalid.

        Expected result:
            - Returns 200 OK status
            - Valid users are in valid_users list
            - Invalid users are in invalid_users list
            - Summary contains correct counts
        """
        self.client.force_authenticate(user=self.admin_user)
        request_data = {"users": input_users}
        response = self.client.post(self.url, data=request_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(set(response.data["valid_users"]), set(expected_valid))
        self.assertEqual(set(response.data["invalid_users"]), set(expected_invalid))
        self.assertEqual(response.data["summary"]["total"], len(input_users))
        self.assertEqual(response.data["summary"]["valid_count"], len(expected_valid))
        self.assertEqual(response.data["summary"]["invalid_count"], len(expected_invalid))

    @data(
        # All users invalid
        (["nonexistent1", "nonexistent2"], [], ["nonexistent1", "nonexistent2"]),
        # All invalid emails
        (["fake1@example.com", "fake2@example.com"], [], ["fake1@example.com", "fake2@example.com"]),
        # Single invalid user
        (["nonexistent_user"], [], ["nonexistent_user"]),
        # Single invalid email
        (["fake@example.com"], [], ["fake@example.com"]),
    )
    @unpack
    def test_post_all_users_invalid(self, input_users: list, expected_valid: list, expected_invalid: list):
        """Test user validation when all users are invalid.

        Expected result:
            - Returns 200 OK status
            - valid_users list is empty
            - All users are in invalid_users list
            - Summary contains correct counts
        """
        self.client.force_authenticate(user=self.admin_user)
        request_data = {"users": input_users}
        response = self.client.post(self.url, data=request_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["valid_users"], expected_valid)
        self.assertEqual(set(response.data["invalid_users"]), set(expected_invalid))
        self.assertEqual(response.data["summary"]["total"], len(input_users))
        self.assertEqual(response.data["summary"]["valid_count"], len(expected_valid))
        self.assertEqual(response.data["summary"]["invalid_count"], len(expected_invalid))

    @data(
        # Missing users field
        {},
        {"other_field": "value"},
        # Empty users list (not allowed by serializer)
        {"users": []},
        # Invalid data types
        {"users": "not_a_list"},
        {"users": [{"not": "string"}]},
        # Null values
        {"users": None},
        {"users": [None, "admin_1"]},
        # Users with strings too long (over 255 characters)
        {"users": ["a" * 256]},
    )
    def test_post_invalid_request_data(self, request_data: dict):
        """Test user validation with invalid request data.

        Test cases:
            - Missing required fields
            - Empty users list (not allowed)
            - Invalid data types
            - Null values
            - Strings exceeding max length

        Expected result:
            - Returns 400 BAD REQUEST status
        """
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.post(self.url, data=request_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @data(
        # Unauthenticated request
        (None, status.HTTP_401_UNAUTHORIZED),
        # Admin user with proper permissions (superuser)
        ("admin_1", status.HTTP_200_OK),
        # Regular user without required permissions (only LIBRARY_USER)
        ("regular_1", status.HTTP_403_FORBIDDEN),
        # Regular user with LIBRARY_ADMIN role (has MANAGE_LIBRARY_TEAM permission)
        ("regular_5", status.HTTP_200_OK),
    )
    @unpack
    def test_post_authentication_and_permissions(self, username: str, expected_status: int):
        """Test user validation with different authentication and permission scenarios.

        Expected result:
            - Returns 401 UNAUTHORIZED for unauthenticated requests
            - Returns 403 FORBIDDEN for authenticated users without permissions
            - Returns 200 OK for users with proper permissions
        """
        if username:
            user = User.objects.get(username=username)
            self.client.force_authenticate(user=user)
        else:
            self.client.force_authenticate(user=None)
        request_data = {"users": ["admin_1", "regular_1"]}
        response = self.client.post(self.url, data=request_data, format="json")
        self.assertEqual(response.status_code, expected_status)
        if expected_status == status.HTTP_200_OK:
            self.assertIn("valid_users", response.data)
            self.assertIn("invalid_users", response.data)
            self.assertIn("summary", response.data)
            self.assertIn("total", response.data["summary"])
            self.assertIn("valid_count", response.data["summary"])
            self.assertIn("invalid_count", response.data["summary"])

    def test_post_serializer_deduplication(self):
        """Test that serializer properly deduplicates users while preserving order.

        The serializer automatically removes duplicates using dict.fromkeys().

        Expected result:
            - Returns 200 OK status
            - Duplicates are automatically removed by the serializer
            - Order is preserved for first occurrence
        """
        self.client.force_authenticate(user=self.admin_user)
        request_data = {"users": ["admin_1", "admin_1", "nonexistent", "nonexistent", "regular_1"]}
        response = self.client.post(self.url, data=request_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["valid_users"], ["admin_1", "regular_1"])
        self.assertEqual(response.data["invalid_users"], ["nonexistent"])
        self.assertEqual(response.data["summary"]["total"], 3)
        self.assertEqual(response.data["summary"]["valid_count"], 2)
        self.assertEqual(response.data["summary"]["invalid_count"], 1)

    def test_post_large_user_list(self):
        """Test user validation with a large list of users.

        Expected result:
            - Returns 200 OK status
            - Correctly processes all users in the list
            - Response structure is maintained
        """
        self.client.force_authenticate(user=self.admin_user)
        valid_users = ["admin_1", "admin_2", "regular_1", "regular_2"]
        invalid_users = [f"nonexistent_{i}" for i in range(10)]
        all_users = valid_users + invalid_users
        request_data = {"users": all_users}
        response = self.client.post(self.url, data=request_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(set(response.data["valid_users"]), set(valid_users))
        self.assertEqual(set(response.data["invalid_users"]), set(invalid_users))
        self.assertEqual(response.data["summary"]["total"], len(all_users))
        self.assertEqual(response.data["summary"]["valid_count"], len(valid_users))
        self.assertEqual(response.data["summary"]["invalid_count"], len(invalid_users))

    def test_post_response_serializer_structure(self):
        """Test that response matches UserValidationAPIViewResponseSerializer structure.

        Expected result:
            - Returns 200 OK status
            - Response contains all required fields
            - Field types match serializer definition
        """
        self.client.force_authenticate(user=self.admin_user)
        request_data = {"users": ["admin_1", "nonexistent"]}
        response = self.client.post(self.url, data=request_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        required_fields = ["valid_users", "invalid_users", "summary"]
        for field in required_fields:
            self.assertIn(field, response.data)
        summary_fields = ["total", "valid_count", "invalid_count"]
        for field in summary_fields:
            self.assertIn(field, response.data["summary"])
            self.assertIsInstance(response.data["summary"][field], int)
        self.assertIsInstance(response.data["valid_users"], list)
        self.assertIsInstance(response.data["invalid_users"], list)

    def test_post_inactive_user_validation(self):
        """Test that inactive users are returned as invalid.

        Expected result:
            - Inactive users appear in invalid_users list
            - Summary counts reflect inactive users as invalid
            - Active users appear in valid_users list
        """
        User.objects.create(username="inactive_user", email="inactive@example.com", is_active=False)
        self.client.force_authenticate(user=self.admin_user)
        request_data = {"users": ["inactive_user", "inactive@example.com", "admin_1"]}
        response = self.client.post(self.url, data=request_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("inactive_user", response.data["invalid_users"])
        self.assertIn("inactive@example.com", response.data["invalid_users"])
        self.assertIn("admin_1", response.data["valid_users"])
        self.assertEqual(response.data["summary"]["total"], 3)
        self.assertEqual(response.data["summary"]["valid_count"], 1)
        self.assertEqual(response.data["summary"]["invalid_count"], 2)

    def test_post_with_validate_users_exception(self):
        """Test handling of unexpected exceptions from validate_users."""
        self.client.force_authenticate(user=self.admin_user)
        with patch.object(api, "validate_users") as mock_validate_users:
            mock_validate_users.side_effect = Exception("Database connection error")
            request_data = {"users": ["admin_1"]}
            response = self.client.post(self.url, data=request_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data["message"], "An error occurred while validating users")

    def test_post_global_permission_inheritance(self):
        """Test that UserValidationAPIView properly inherits from AnyScopePermission class."""
        self.assertIn(AnyScopePermission, UserValidationAPIView.permission_classes)

    def test_post_multiple_roles_user_access(self):
        """Test access for a user with multiple roles that include management permissions."""
        test_user = User.objects.create(username="multi_role_user", email="multi@example.com")
        assign_role_to_user_in_scope(
            user_external_key="multi_role_user",
            role_external_key=roles.LIBRARY_ADMIN.external_key,
            scope_external_key="lib:Org1:LIB1",
        )
        assign_role_to_user_in_scope(
            user_external_key="multi_role_user",
            role_external_key=roles.LIBRARY_USER.external_key,
            scope_external_key="lib:Org2:LIB2",
        )
        self.client.force_authenticate(user=test_user)
        request_data = {"users": ["admin_1", "regular_1"]}
        response = self.client.post(self.url, data=request_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_post_empty_role_assignments_denied(self):
        """Test that a user with no role assignments is properly denied access."""
        test_user = User.objects.create(username="no_roles_user", email="noroles@example.com")
        self.client.force_authenticate(user=test_user)
        request_data = {"users": ["admin_1", "regular_1"]}
        response = self.client.post(self.url, data=request_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


@ddt
class TestBulkPutScopesAllLogic(ViewTestMixin):
    """Test that DynamicScopePermission enforces AND logic across scopes in bulk PUT.

    validate_permissions uses OR logic (any permission suffices per scope), but
    DynamicScopePermission wraps that with all(...for sv in scopes_list), meaning
    the user must pass the permission check for EVERY scope in the list.

    Three users illustrate the difference between specific-scope, org-level, and platform-level permissions:
      - course_admin: COURSE_ADMIN on COURSE_SCOPE_ORG1 only (specific course).
      - course_admin_org: COURSE_ADMIN on COURSE_ORG1_GLOB (all courses in Org1).
      - course_admin_platform: COURSE_ADMIN on PLATFORM_COURSE_GLOB (all courses on the platform).
    """

    ANOTHER_COURSE_SCOPE = "course-v1:Org2+COURSE2+2024"
    _COURSE_ASSIGNMENTS = [
        {
            "subject_name": "course_admin",
            "role_name": roles.COURSE_ADMIN.external_key,
            "scope_name": COURSE_SCOPE_ORG1,
        },
        {
            "subject_name": "course_admin_org",
            "role_name": roles.COURSE_ADMIN.external_key,
            "scope_name": COURSE_ORG1_GLOB,
        },
        {
            "subject_name": "course_admin_platform",
            "role_name": roles.COURSE_ADMIN.external_key,
            "scope_name": PLATFORM_COURSE_GLOB,
        },
    ]

    def setUp(self):
        super().setUp()
        self.user = User.objects.get(username="course_admin")
        self.client.force_authenticate(user=self.user)
        self.url = reverse("openedx_authz:role-user-list")
        self._assign_roles_to_users(assignments=self._COURSE_ASSIGNMENTS)

    def _put_course(self, scopes):
        """Send a bulk PUT assigning COURSE_ADMIN to regular_2 for the given course scopes.

        Patches scope existence checks so validation does not depend on the database.
        """
        request_data = {"role": roles.COURSE_ADMIN.external_key, "scopes": scopes, "users": ["regular_2"]}
        with (
            patch.object(api.CourseOverviewData, "exists", return_value=True),
            patch.object(api.OrgCourseOverviewGlobData, "exists", return_value=True),
        ):
            return self.client.put(self.url, data=request_data, format="json")

    def _put_lib(self, scopes):
        """Send a bulk PUT assigning LIBRARY_ADMIN to regular_2 for the given library scopes.

        Patches ContentLibraryData.exists so validation does not depend on the database.
        """
        request_data = {"role": roles.LIBRARY_ADMIN.external_key, "scopes": scopes, "users": ["regular_2"]}
        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            return self.client.put(self.url, data=request_data, format="json")

    def test_all_scopes_permitted_succeeds(self):
        """course_admin has permission on their specific scope → 207."""
        response = self._put_course([COURSE_SCOPE_ORG1])
        self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)

    def test_one_scope_not_permitted_denied(self):
        """User lacks permission on one of the scopes → 403.

        course_admin has no role on ANOTHER_COURSE_SCOPE, so the all() check must
        fail even though they pass for COURSE_SCOPE_ORG1.
        """
        response = self._put_course([COURSE_SCOPE_ORG1, self.ANOTHER_COURSE_SCOPE])
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_course_user_cannot_add_library_roles(self):
        """A course-only user is denied when trying to assign library roles.

        course_admin has no library permissions at all, so a bulk PUT targeting
        a library scope must be denied regardless of the OR logic inside
        validate_permissions.
        """
        response = self._put_lib(["lib:Org1:LIB1"])
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @data(
        # course_admin has COURSE_ADMIN on the specific course only.
        # Passes for the exact scope, but fails for the org-level glob or any combo including it.
        ("course_admin", [COURSE_SCOPE_ORG1], status.HTTP_207_MULTI_STATUS),
        ("course_admin", [COURSE_ORG1_GLOB], status.HTTP_403_FORBIDDEN),
        ("course_admin", [COURSE_SCOPE_ORG1, COURSE_ORG1_GLOB], status.HTTP_403_FORBIDDEN),
        # course_admin_org has COURSE_ADMIN on the org-level glob.
        # Via Casbin glob matching, this covers both the glob itself and any specific course within the org.
        ("course_admin_org", [COURSE_SCOPE_ORG1], status.HTTP_207_MULTI_STATUS),
        ("course_admin_org", [COURSE_ORG1_GLOB], status.HTTP_207_MULTI_STATUS),
        ("course_admin_org", [COURSE_SCOPE_ORG1, COURSE_ORG1_GLOB], status.HTTP_207_MULTI_STATUS),
    )
    @unpack
    def test_scope_permission_vs_org_permission(self, username, scopes, expected_status):
        """A user with a specific-scope role and one with an org-level role behave differently
        when bulk PUT includes the org-level glob alongside specific scopes.

        course_admin (specific scope) fails on any scope list that includes the org glob,
        because they have no permission at that level.
        course_admin_org (org-level glob) passes for both the glob and any specific course
        within that org, thanks to Casbin's glob matching.
        """
        user = User.objects.get(username=username)
        self.client.force_authenticate(user=user)
        response = self._put_course(scopes)
        self.assertEqual(response.status_code, expected_status)

    @data(
        # course_admin and course_admin_org lack permission at the platform glob.
        ("course_admin", [PLATFORM_COURSE_GLOB], status.HTTP_403_FORBIDDEN),
        ("course_admin", [COURSE_SCOPE_ORG1, PLATFORM_COURSE_GLOB], status.HTTP_403_FORBIDDEN),
        ("course_admin_org", [PLATFORM_COURSE_GLOB], status.HTTP_403_FORBIDDEN),
        ("course_admin_org", [COURSE_ORG1_GLOB, PLATFORM_COURSE_GLOB], status.HTTP_403_FORBIDDEN),
        # course_admin_platform has COURSE_ADMIN on the platform glob.
        # Via Casbin glob matching, this covers the platform glob and any org or course scope.
        ("course_admin_platform", [PLATFORM_COURSE_GLOB], status.HTTP_207_MULTI_STATUS),
        ("course_admin_platform", [COURSE_ORG1_GLOB], status.HTTP_207_MULTI_STATUS),
        ("course_admin_platform", [COURSE_SCOPE_ORG1], status.HTTP_207_MULTI_STATUS),
        ("course_admin_platform", [PLATFORM_COURSE_GLOB, COURSE_ORG1_GLOB], status.HTTP_207_MULTI_STATUS),
    )
    @unpack
    def test_scope_permission_vs_platform_permission(self, username, scopes, expected_status):
        """Users with course- or org-level roles cannot assign at the platform glob.

        course_admin (specific scope) and course_admin_org (org glob) fail on any scope
        list that includes the platform glob, because they have no permission at that level.
        course_admin_platform (platform glob) passes for the platform glob and any org or
        specific course within it, thanks to Casbin's glob matching.
        """
        user = User.objects.get(username=username)
        self.client.force_authenticate(user=user)

        response = self._put_course(scopes)

        self.assertEqual(response.status_code, expected_status)


@ddt
class TestPlatformGlobLibraryRoleAssignment(ViewTestMixin):
    """Test that a platform-level library_admin can assign library roles at lib:*.

    Three users illustrate the difference between specific-scope, org-level, and
    platform-level library permissions:
      - library_admin: LIBRARY_ADMIN on LIB_SCOPE_ORG1 only (specific library).
      - library_admin_org: LIBRARY_ADMIN on LIB_ORG1_GLOB (all libraries in Org1).
      - library_admin_platform: LIBRARY_ADMIN on PLATFORM_LIBRARY_GLOB (all libraries).
    """

    _LIBRARY_ASSIGNMENTS = [
        {
            "subject_name": "library_admin",
            "role_name": roles.LIBRARY_ADMIN.external_key,
            "scope_name": LIB_SCOPE_ORG1,
        },
        {
            "subject_name": "library_admin_org",
            "role_name": roles.LIBRARY_ADMIN.external_key,
            "scope_name": LIB_ORG1_GLOB,
        },
        {
            "subject_name": "library_admin_platform",
            "role_name": roles.LIBRARY_ADMIN.external_key,
            "scope_name": PLATFORM_LIBRARY_GLOB,
        },
    ]

    def setUp(self):
        super().setUp()
        self.url = reverse("openedx_authz:role-user-list")
        self._assign_roles_to_users(assignments=self._LIBRARY_ASSIGNMENTS)

    def _put_lib(self, scopes, role):
        """Send a bulk PUT assigning the given library role for the given scopes."""
        request_data = {"role": role, "scopes": scopes, "users": ["regular_2"]}
        with (
            patch.object(api.ContentLibraryData, "exists", return_value=True),
            patch.object(api.OrgContentLibraryGlobData, "exists", return_value=True),
            patch.object(api.PlatformContentLibraryGlobData, "exists", return_value=True),
        ):
            return self.client.put(self.url, data=request_data, format="json")

    @data(
        roles.LIBRARY_ADMIN.external_key,
        roles.LIBRARY_AUTHOR.external_key,
        roles.LIBRARY_CONTRIBUTOR.external_key,
        roles.LIBRARY_USER.external_key,
    )
    def test_platform_library_admin_can_assign_any_role_globally(self, role):
        """A platform library_admin can assign any library role at lib:*."""
        user = User.objects.get(username="library_admin_platform")
        self.client.force_authenticate(user=user)

        response = self._put_lib([PLATFORM_LIBRARY_GLOB], role)

        self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
        self.assertEqual(len(response.data["completed"]), 1)
        self.assertEqual(response.data["completed"][0]["scope"], PLATFORM_LIBRARY_GLOB)

    @data(
        # library_admin and library_admin_org lack permission at the platform glob.
        ("library_admin", [PLATFORM_LIBRARY_GLOB], status.HTTP_403_FORBIDDEN),
        ("library_admin", [LIB_SCOPE_ORG1, PLATFORM_LIBRARY_GLOB], status.HTTP_403_FORBIDDEN),
        ("library_admin_org", [PLATFORM_LIBRARY_GLOB], status.HTTP_403_FORBIDDEN),
        ("library_admin_org", [LIB_ORG1_GLOB, PLATFORM_LIBRARY_GLOB], status.HTTP_403_FORBIDDEN),
        # library_admin_platform has LIBRARY_ADMIN on the platform glob.
        # Via Casbin glob matching, this covers the platform glob and any org or library scope.
        ("library_admin_platform", [PLATFORM_LIBRARY_GLOB], status.HTTP_207_MULTI_STATUS),
        ("library_admin_platform", [LIB_ORG1_GLOB], status.HTTP_207_MULTI_STATUS),
        ("library_admin_platform", [LIB_SCOPE_ORG1], status.HTTP_207_MULTI_STATUS),
        ("library_admin_platform", [PLATFORM_LIBRARY_GLOB, LIB_ORG1_GLOB], status.HTTP_207_MULTI_STATUS),
    )
    @unpack
    def test_scope_permission_vs_platform_permission(self, username, scopes, expected_status):
        """Users with library- or org-level roles cannot assign at the platform glob.

        library_admin (specific scope) and library_admin_org (org glob) fail on any scope
        list that includes the platform glob, because they have no permission at that level.
        library_admin_platform (platform glob) passes for the platform glob and any org or
        specific library within it, thanks to Casbin's glob matching.
        """
        user = User.objects.get(username=username)
        self.client.force_authenticate(user=user)

        response = self._put_lib(scopes, roles.LIBRARY_ADMIN.external_key)

        self.assertEqual(response.status_code, expected_status)
