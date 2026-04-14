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
from organizations.models import Organization
from rest_framework import status
from rest_framework.test import APIClient

from openedx_authz import api
from openedx_authz.api.users import assign_role_to_user_in_scope
from openedx_authz.constants import permissions, roles
from openedx_authz.rest_api.data import RoleOperationError, RoleOperationStatus
from openedx_authz.rest_api.v1.permissions import AnyScopePermission, DynamicScopePermission
from openedx_authz.rest_api.v1.views import UserValidationAPIView
from openedx_authz.tests.api.test_roles import BaseRolesTestCase

User = get_user_model()


def get_user_map_without_profile(usernames: list[str]) -> dict[str, User]:
    """
    Test version of ``get_user_map`` that doesn't use select_related('profile').

    The generic Django User model doesn't have a profile relation,
    so we override this in tests to avoid FieldError.
    """
    users = User.objects.filter(username__in=usernames)
    return {user.username: user for user in users}


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
    def setUpTestData(cls):
        """Set up test fixtures once for the entire test class."""
        super().setUpTestData()
        cls.create_admin_users(quantity=3)
        cls.create_regular_users(quantity=10)

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
        [{"action": "edit_library"}],
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
        [
            {"action": "edit_library", "scope": "lib:Org1:LIB1"},
            {"action": "edit_library"},
        ],
    )
    def test_permission_validation_invalid_data(self, invalid_data: list[dict]):
        """Test permission validation with invalid request data.

        Expected result:
            - Returns 400 BAD REQUEST status
        """
        response = self.client.post(self.url, data=invalid_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

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

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.client.force_authenticate(user=self.admin_user)
        self.url = reverse("openedx_authz:role-user-list")
        self.get_user_map_patcher = patch(
            "openedx_authz.rest_api.v1.views.get_user_map",
            side_effect=get_user_map_without_profile,
        )
        self.get_user_map_patcher.start()

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
class TestAdminConsoleOrgsAPIView(ViewTestMixin):
    """Test suite for AdminConsoleOrgsAPIView."""

    @classmethod
    def setUpClass(cls):
        """Assign a course role to regular_9 for COURSES_VIEW_COURSE_TEAM permission tests."""
        super().setUpClass()
        cls._assign_roles_to_users(
            [
                {
                    "subject_name": "regular_9",
                    "role_name": roles.COURSE_STAFF.external_key,
                    "scope_name": "course-v1:Org1+COURSE1+2024",
                },
            ]
        )

    @classmethod
    def setUpTestData(cls):
        """Create Organization fixtures."""
        super().setUpTestData()

        Organization.objects.bulk_create(
            [
                Organization(name="Alpha University", short_name="AlphaU"),
                Organization(name="Beta Institute", short_name="BetaI"),
                Organization(name="Gamma College", short_name="GammaC"),
            ]
        )

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.url = reverse("openedx_authz:orgs-list")

    def test_get_orgs_returns_all(self):
        """Test that all orgs are returned when no search param is provided.

        Expected result:
            - Returns 200 OK status
            - Returns all 3 orgs
        """
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 3)
        self.assertEqual(len(response.data["results"]), 3)

    @data(
        # Match by name
        ("Alpha", 1),
        ("university", 1),
        # Match by short_name
        ("BetaI", 1),
        ("gamma", 1),
        # Partial match across multiple orgs
        ("a", 3),
        # No match
        ("nonexistent", 0),
    )
    @unpack
    def test_get_orgs_search(self, search_term: str, expected_count: int):
        """Test filtering orgs by name or short_name via the search param.

        Expected result:
            - Returns 200 OK status
            - Returns only orgs matching the search term
        """
        response = self.client.get(self.url, {"search": search_term})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)
        self.assertEqual(len(response.data["results"]), expected_count)

    @data(
        ({}, 3, False),
        ({"page": 1, "page_size": 2}, 2, True),
        ({"page": 2, "page_size": 2}, 1, False),
        ({"page": 1, "page_size": 3}, 3, False),
    )
    @unpack
    def test_get_orgs_pagination(self, query_params: dict, expected_count: int, has_next: bool):
        """Test pagination of org results.

        Expected result:
            - Returns 200 OK status
            - Returns correct page size and next link
        """
        response = self.client.get(self.url, query_params)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), expected_count)
        if has_next:
            self.assertIsNotNone(response.data["next"])
        else:
            self.assertIsNone(response.data["next"])

    def test_get_orgs_response_shape(self):
        """Test that each org result contains the expected fields.

        Expected result:
            - Each result has id, name, and short_name fields
        """
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        result = response.data["results"][0]
        self.assertIn("id", result)
        self.assertIn("name", result)
        self.assertIn("short_name", result)

    def test_get_orgs_excludes_inactive(self):
        """Test that inactive orgs are not returned.

        Expected result:
            - Returns 200 OK status
            - Inactive orgs are excluded from results
        """
        Organization.objects.create(name="Inactive Org", short_name="InactiveO", active=False)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 3)
        result_names = [org["name"] for org in response.data["results"]]
        self.assertNotIn("Inactive Org", result_names)

    @data(
        # Only VIEW_LIBRARY_TEAM (library_user role in a lib scope)
        ("regular_1", status.HTTP_200_OK),
        # Only COURSES_VIEW_COURSE_TEAM (course_staff role in a course scope)
        ("regular_9", status.HTTP_200_OK),
        # No relevant permissions
        ("regular_10", status.HTTP_403_FORBIDDEN),
        # Superuser
        ("admin_1", status.HTTP_200_OK),
    )
    @unpack
    def test_get_orgs_permissions(self, username: str, expected_status: int):
        """Test access control for AdminConsoleOrgsAPIView.

        Test cases:
            - User with only VIEW_LIBRARY_TEAM (via library role): allowed
            - User with only COURSES_VIEW_COURSE_TEAM (via course role): allowed
            - User with neither permission: forbidden
            - Superuser/staff: allowed

        Expected result:
            - Returns appropriate status code based on user permissions

        """
        user = User.objects.get(username=username)
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, expected_status)

    def test_get_orgs_user_with_both_permissions_allowed(self):
        """Test that a user with both VIEW_LIBRARY_TEAM and COURSES_VIEW_COURSE_TEAM can access the endpoint.

        Expected result:
            - Returns 200 OK status
        """
        # regular_1 has library_user (VIEW_LIBRARY_TEAM); assign a course role too
        self._assign_roles_to_users(
            [
                {
                    "subject_name": "regular_1",
                    "role_name": roles.COURSE_STAFF.external_key,
                    "scope_name": "course-v1:Org1+COURSE1+2024",
                },
            ]
        )
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_get_orgs_unauthenticated(self):
        """Test that unauthenticated requests are rejected.

        Expected result:
            - Returns 401 UNAUTHORIZED status

        """
        self.client.force_authenticate(user=None)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


@ddt
class TestTeamMembersAPIView(ViewTestMixin):
    """
    Test suite for TeamMembersAPIView.

    Setup summary (from ViewTestMixin.setUpClass):
        lib:Org1:LIB1 → admin_1 (library_admin), regular_1 (library_user), regular_2 (library_user)  [3 users]
        lib:Org2:LIB2 → admin_2 (library_user),  regular_3 (library_user),  regular_4 (library_user) [3 users]
        lib:Org3:LIB3 → admin_3 (library_admin), regular_5 (library_admin), regular_6 (library_author),
                        regular_7 (library_contributor), regular_8 (library_user)                    [5 users]

    Total unique users with assignments: 11
    (admin_1..3 are staff/superuser; regular_1..8 are plain users)

    Visibility via filter_allowed_assignments:
        - Staff/superuser: sees all 11 users (is_admin_or_superuser_check grants VIEW_LIBRARY_TEAM on lib scopes)
        - regular_1 (library_user in Org1:LIB1): VIEW_LIBRARY_TEAM granted → sees Org1 members (3)
        - regular_3 (library_user in Org2:LIB2): VIEW_LIBRARY_TEAM granted → sees Org2 members (3)
        - regular_6 (library_author in Org3:LIB3): VIEW_LIBRARY_TEAM granted → sees Org3 members (5)
    """

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.url = reverse("openedx_authz:user-list")
        self.get_user_map_patcher = patch(
            "openedx_authz.api.utils.get_user_map",
            side_effect=get_user_map_without_profile,
        )
        self.get_user_map_patcher.start()
        self.addCleanup(self.get_user_map_patcher.stop)

    # -------------------------------------------------------------------- #
    # Visibility: calling user only sees assignments it has view access to #
    # -------------------------------------------------------------------- #

    @data(
        # Staff/superuser sees all users across all scopes
        ("admin_1", status.HTTP_200_OK, 11),
        # regular_1 has LIBRARY_USER in lib:Org1:LIB1 (VIEW_LIBRARY_TEAM granted) → sees only Org1 members
        ("regular_1", status.HTTP_200_OK, 3),
        # regular_3 has LIBRARY_USER in lib:Org2:LIB2 (VIEW_LIBRARY_TEAM granted) → sees only Org2 members
        ("regular_3", status.HTTP_200_OK, 3),
        # regular_6 has LIBRARY_AUTHOR in lib:Org3:LIB3 (VIEW_LIBRARY_TEAM granted) → sees only Org3 members
        ("regular_6", status.HTTP_200_OK, 5),
        # regular_9 has no assignments → 403 (AnyScopePermission requires at least one relevant permission)
        ("regular_9", status.HTTP_403_FORBIDDEN, None),
    )
    @unpack
    def test_visibility_limited_to_accessible_scopes(
        self, username: str, expected_status: int, expected_count: int | None
    ):
        """Calling user only sees assignments for scopes it has VIEW_*_TEAM access to.

        Expected result:
            - Staff/superuser sees all users across all scopes.
            - Regular users only see members of scopes they have VIEW_*_TEAM permission for.
            - Users with no relevant permissions get 403.
        """
        user = User.objects.get(username=username)
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, expected_status)
        if expected_count is not None:
            self.assertEqual(response.data["count"], expected_count)

    def test_unauthenticated_returns_401(self):
        """Unauthenticated requests are rejected.

        Expected result:
            - Returns 401 UNAUTHORIZED.
        """
        self.client.force_authenticate(user=None)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # -------------------------------------------------------------------- #
    # Filter by scopes                                                     #
    # -------------------------------------------------------------------- #

    @data(
        # Single scope
        ("lib:Org1:LIB1", 3),
        ("lib:Org2:LIB2", 3),
        ("lib:Org3:LIB3", 5),
        # Multiple scopes (users are unique per scope, no overlap)
        ("lib:Org1:LIB1,lib:Org2:LIB2", 6),
        ("lib:Org1:LIB1,lib:Org3:LIB3", 8),
        ("lib:Org1:LIB1,lib:Org2:LIB2,lib:Org3:LIB3", 11),
        # Non-existent scope returns no results
        ("lib:Org99:NOLIB", 0),
    )
    @unpack
    def test_filter_by_scopes(self, scopes: str, expected_count: int):
        """Results are filtered to the requested scopes.

        Expected result:
            - Only users with assignments in the given scope(s) are returned.
            - Multiple scopes are OR-combined.
        """
        response = self.client.get(self.url, {"scopes": scopes})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)

    # ------------------------------------------------------------------ #
    # Filter by orgs                                                     #
    # ------------------------------------------------------------------ #

    @data(
        # Single org
        ("Org1", 3),
        ("Org2", 3),
        ("Org3", 5),
        # Multiple orgs
        ("Org1,Org2", 6),
        ("Org1,Org3", 8),
        ("Org1,Org2,Org3", 11),
        # Non-existent org returns no results
        ("OrgX", 0),
    )
    @unpack
    def test_filter_by_orgs(self, orgs: str, expected_count: int):
        """Results are filtered to the requested orgs.

        Expected result:
            - Only users with assignments in the given org(s) are returned.
            - Multiple orgs are OR-combined.
        """
        response = self.client.get(self.url, {"orgs": orgs})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)

    # ------------------------------------------------------------------ #
    # Search (username, full_name, email)                                #
    # ------------------------------------------------------------------ #

    @data(
        # Exact username match
        ("admin_1", 1),
        # Partial username match
        ("admin", 3),
        ("regular", 8),
        # Email match
        ("admin_1@example.com", 1),
        ("@example.com", 11),
        # No match
        ("nonexistent", 0),
    )
    @unpack
    def test_search(self, search: str, expected_count: int):
        """Search filters by username, full_name, or email (case-insensitive).

        Expected result:
            - Returns only users whose username, full_name, or email contains the search term.
        """
        response = self.client.get(self.url, {"search": search})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)

    # ------------------------------------------------------------------ #
    # Sorting                                                            #
    # ------------------------------------------------------------------ #

    @data(
        ("username", "asc"),
        ("username", "desc"),
        ("email", "asc"),
        ("email", "desc"),
        ("full_name", "asc"),
        ("full_name", "desc"),
    )
    @unpack
    def test_sorting(self, sort_by: str, order: str):
        """Results can be sorted by username, full_name, or email in asc/desc order.

        Expected result:
            - Returns 200 OK.
            - Results are ordered according to the requested field and direction.
        """
        response = self.client.get(self.url, {"sort_by": sort_by, "order": order})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        values = [item[sort_by] for item in response.data["results"]]
        expected = sorted(values, key=lambda v: (v or "").lower(), reverse=order == "desc")
        self.assertEqual(values, expected)

    @data(
        {"sort_by": "invalid"},
        {"order": "ascending"},
        {"order": "descending"},
    )
    def test_sorting_invalid_params(self, query_params: dict):
        """Invalid sort_by or order values return 400.

        Expected result:
            - Returns 400 BAD REQUEST.
        """
        response = self.client.get(self.url, query_params)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # ------------------------------------------------------------------ #
    # Pagination                                                         #
    # ------------------------------------------------------------------ #

    @data(
        ({"page": 1, "page_size": 5}, 5, True),
        ({"page": 2, "page_size": 5}, 5, True),
        ({"page": 3, "page_size": 5}, 1, False),
        ({"page": 1, "page_size": 11}, 11, False),
        ({"page": 1, "page_size": 6}, 6, True),
    )
    @unpack
    def test_pagination(self, query_params: dict, expected_page_count: int, has_next: bool):
        """Results are paginated correctly.

        Expected result:
            - Returns 200 OK.
            - Page contains the expected number of items.
            - `next` link is present only when more pages exist.
        """
        response = self.client.get(self.url, query_params)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 11)
        self.assertEqual(len(response.data["results"]), expected_page_count)
        if has_next:
            self.assertIsNotNone(response.data["next"])
        else:
            self.assertIsNone(response.data["next"])

    # ------------------------------------------------------------------ #
    # Response shape                                                     #
    # ------------------------------------------------------------------ #

    def test_response_shape(self):
        """Each result item contains the expected fields.

        Expected result:
            - Returns 200 OK.
            - Each item has username, full_name, email, and assignation_count.
        """
        response = self.client.get(self.url, {"scopes": "lib:Org1:LIB1"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for item in response.data["results"]:
            self.assertIn("username", item)
            self.assertIn("full_name", item)
            self.assertIn("email", item)
            self.assertIn("assignation_count", item)
            self.assertEqual(item["assignation_count"], 1)


@ddt
class TestTeamMemberAssignmentsAPIView(ViewTestMixin):
    """
    Test suite for TeamMemberAssignmentsAPIView.

    Setup summary (from ViewTestMixin.setUpClass):
        lib:Org1:LIB1 → admin_1 (library_admin), regular_1 (library_user), regular_2 (library_user)
        lib:Org2:LIB2 → admin_2 (library_user),  regular_3 (library_user),  regular_4 (library_user)
        lib:Org3:LIB3 → admin_3 (library_admin), regular_5 (library_admin), regular_6 (library_author),
                        regular_7 (library_contributor), regular_8 (library_user)

    URL: /api/authz/v1/users/<username>/assignments/
    Response fields per item: is_superadmin, role, org, scope, permission_count

    Superadmin entry:
        admin_1..3 are staff/superusers. Querying any of them always adds one
        SuperAdminAssignmentData entry: role="django.superuser" (or "django.staff"),
        org="*", scope="*", permission_count=None, is_superadmin=True.
        This entry is always included regardless of org/role filters, since those
        filters are applied only to the role assignments, not to the superadmin entry.

    Visibility via filter_allowed_assignments:
        - Staff/superuser: sees all role assignments for any user, plus the superadmin
          entry when the target is a superadmin.
        - regular_1 (library_user in Org1:LIB1): sees only Org1:LIB1 role assignments,
          plus the superadmin entry when the target is a superadmin.
        - regular_9 (no assignments): rejected with 403 by AnyScopePermission
          (requires at least one VIEW_LIBRARY_TEAM or COURSES_VIEW_COURSE_TEAM permission).
    """

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.get_user_map_patcher = patch(
            "openedx_authz.api.utils.get_user_map",
            side_effect=get_user_map_without_profile,
        )
        self.get_user_map_patcher.start()
        self.addCleanup(self.get_user_map_patcher.stop)

    def _url(self, username: str) -> str:
        return reverse("openedx_authz:user-assignment-list", kwargs={"username": username})

    # -------------------------------------------------------------------- #
    # Visibility: calling user only sees assignments it has view access to #
    # -------------------------------------------------------------------- #

    @data(
        # Staff/superuser targets get 1 superadmin entry + their role assignment(s)
        ("admin_1", "admin_1", status.HTTP_200_OK, 2),  # superadmin entry + library_admin in Org1
        ("admin_1", "admin_2", status.HTTP_200_OK, 2),  # superadmin entry + library_user in Org2
        ("admin_1", "admin_3", status.HTTP_200_OK, 2),  # superadmin entry + library_admin in Org3
        # Regular user targets get only their role assignments (no superadmin entry)
        ("admin_1", "regular_5", status.HTTP_200_OK, 1),
        # The superadmin entry is always included for superadmin targets, visible to all callers
        (
            "regular_1",
            "admin_1",
            status.HTTP_200_OK,
            2,
        ),  # superadmin entry + library_admin in Org1 (visible via Org1 access)
        # regular_1 cannot see admin_2's Org2 role assignment, but superadmin entry is still included
        ("regular_1", "admin_2", status.HTTP_200_OK, 1),  # superadmin entry only
        # regular_9 has no assignments → 403 (AnyScopePermission requires at least one relevant permission)
        ("regular_9", "admin_1", status.HTTP_403_FORBIDDEN, None),
    )
    @unpack
    def test_visibility_limited_to_accessible_scopes(
        self, caller: str, target: str, expected_status: int, expected_count: int | None
    ):
        """Calling user only sees role assignments for scopes it has view access to.

        The superadmin entry is always included when the target is a superadmin,
        regardless of the calling user's permissions.

        Expected result:
            - Superadmin targets always include the superadmin entry.
            - Role assignments are filtered by the calling user's permissions.
            - Regular user targets return only their visible role assignments.
            - Users with no relevant permissions get 403.
        """
        self.client.force_authenticate(user=User.objects.get(username=caller))

        response = self.client.get(self._url(target))

        self.assertEqual(response.status_code, expected_status)
        if expected_count is not None:
            self.assertEqual(response.data["count"], expected_count)

    def test_unauthenticated_returns_401(self):
        """Unauthenticated requests are rejected.

        Expected result:
            - Returns 401 UNAUTHORIZED.
        """
        self.client.force_authenticate(user=None)

        response = self.client.get(self._url("admin_1"))

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_unknown_user_returns_empty(self):
        """Requesting assignments for a non-existent user returns an empty list.

        Expected result:
            - Returns 200 OK with count 0.
        """
        response = self.client.get(self._url("nonexistent_user"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 0)

    # ------------------------------------------------------------------ #
    # Filter by orgs                                                     #
    # ------------------------------------------------------------------ #

    @data(
        # admin_3 has library_admin in lib:Org3:LIB3; superadmin entry is always included
        ("admin_3", "Org3", 2),  # superadmin entry + Org3 role assignment
        ("admin_3", "Org1", 1),  # superadmin entry only (no Org1 role assignment)
        # regular_5 has library_admin in lib:Org3:LIB3 (no superadmin entry)
        ("regular_5", "Org3", 1),
        ("regular_5", "Org1", 0),
        # non-existent org: superadmin entry still included for admin targets
        ("admin_1", "OrgX", 1),  # superadmin entry only
    )
    @unpack
    def test_filter_by_orgs(self, target: str, orgs: str, expected_count: int):
        """Results are filtered to the requested orgs.

        Expected result:
            - Only assignments in the given org(s) are returned.
            - Multiple orgs are OR-combined.
        """
        response = self.client.get(self._url(target), {"orgs": orgs})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)

    def test_filter_by_multiple_orgs(self):
        """Multiple orgs are OR-combined.

        Expected result:
            - Returns assignments matching any of the given orgs.
        """
        # regular_6 has library_author in lib:Org3:LIB3
        # regular_7 has library_contributor in lib:Org3:LIB3
        # Use admin_1 (staff) to see all of regular_8's assignments
        # regular_8 has library_user in lib:Org3:LIB3 only
        response = self.client.get(self._url("regular_8"), {"orgs": "Org1,Org3"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)

    # ------------------------------------------------------------------ #
    # Filter by roles                                                    #
    # ------------------------------------------------------------------ #

    @data(
        # role filter applies only to role assignments; superadmin entry is always included for admin targets
        ("admin_1", roles.LIBRARY_ADMIN.external_key, 2),  # superadmin entry + library_admin
        ("admin_1", roles.LIBRARY_USER.external_key, 1),  # superadmin entry only
        ("regular_5", roles.LIBRARY_ADMIN.external_key, 1),
        ("regular_5", roles.LIBRARY_USER.external_key, 0),
        ("regular_6", roles.LIBRARY_AUTHOR.external_key, 1),
        ("regular_6", roles.LIBRARY_ADMIN.external_key, 0),
        ("admin_1", "non_existent_role", 1),  # superadmin entry only
    )
    @unpack
    def test_filter_by_roles(self, target: str, role_filter: str, expected_count: int):
        """Results are filtered to the requested roles.

        Expected result:
            - Only assignments with the given role(s) are returned.
        """
        response = self.client.get(self._url(target), {"roles": role_filter})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)

    def test_filter_by_multiple_roles(self):
        """Multiple roles are OR-combined for role assignments; superadmin entry always included.

        Expected result:
            - Returns assignments matching any of the given roles, plus the superadmin entry.
        """
        # admin_3 has library_admin in Org3:LIB3; filter for admin + author returns
        # 1 role assignment + 1 superadmin entry = 2
        response = self.client.get(
            self._url("admin_3"),
            {"roles": f"{roles.LIBRARY_ADMIN.external_key},{roles.LIBRARY_AUTHOR.external_key}"},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 2)

    # ------------------------------------------------------------------ #
    # Sorting                                                            #
    # ------------------------------------------------------------------ #

    @data(
        ("role", "asc"),
        ("role", "desc"),
        ("org", "asc"),
        ("org", "desc"),
        ("scope", "asc"),
        ("scope", "desc"),
    )
    @unpack
    def test_sorting(self, sort_by: str, order: str):
        """Results are sorted by role, org, or scope in asc/desc order.

        Uses admin_3, who has 2 items in the response: a superadmin entry
        (role="django.superuser", org="*", scope="*") and a role assignment
        (role="library_admin", org="Org3", scope="lib:Org3:LIB3"). With two
        distinct values per field the sort order is non-trivial and verifiable.

        Expected result:
            - Returns 200 OK.
            - Results are ordered according to the requested field and direction.
        """
        response = self.client.get(self._url("admin_3"), {"sort_by": sort_by, "order": order})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreater(len(response.data["results"]), 1)
        values = [item[sort_by] for item in response.data["results"]]
        expected = sorted(values, key=lambda v: (v or "").lower(), reverse=order == "desc")
        self.assertEqual(values, expected)

    @data(
        {"sort_by": "invalid"},
        {"sort_by": "username"},
        {"order": "ascending"},
        {"order": "descending"},
    )
    def test_sorting_invalid_params(self, query_params: dict):
        """Invalid sort_by or order values return 400.

        Expected result:
            - Returns 400 BAD REQUEST.
        """
        response = self.client.get(self._url("admin_1"), query_params)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # ------------------------------------------------------------------ #
    # Pagination                                                         #
    # ------------------------------------------------------------------ #

    @data(
        ({"page": 1, "page_size": 1}, 1, True),
        ({"page": 2, "page_size": 1}, 1, False),
        ({"page": 1, "page_size": 2}, 2, False),
    )
    @unpack
    def test_pagination(self, query_params: dict, expected_page_count: int, has_next: bool):
        """Results are paginated correctly.

        Assigns regular_8 a second role (library_admin in Org1:LIB1) so it has
        2 assignments visible to admin_1 (staff).

        Expected result:
            - Returns 200 OK.
            - Page contains the expected number of items.
            - `next` link is present only when more pages exist.
        """
        assign_role_to_user_in_scope("regular_8", roles.LIBRARY_ADMIN.external_key, "lib:Org1:LIB1")

        response = self.client.get(self._url("regular_8"), query_params)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), expected_page_count)
        if has_next:
            self.assertIsNotNone(response.data["next"])
        else:
            self.assertIsNone(response.data["next"])

    # ------------------------------------------------------------------ #
    # Response shape                                                     #
    # ------------------------------------------------------------------ #

    def test_response_shape(self):
        """Each result item contains the expected fields.

        admin_1 is a superuser, so the response contains two items:
        - A superadmin entry with role="django.superuser", org="*", scope="*",
          permission_count=None, is_superadmin=True
        - A regular role assignment entry with concrete values and is_superadmin=False

        Expected result:
            - Returns 200 OK.
            - Each item has is_superadmin, role, org, scope, and permission_count.
        """
        response = self.client.get(self._url("admin_1"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 2)

        superadmin_item = next(item for item in response.data["results"] if item["is_superadmin"])
        self.assertIn(superadmin_item["role"], ("django.superuser", "django.staff"))
        self.assertEqual(superadmin_item["org"], "*")
        self.assertEqual(superadmin_item["scope"], "*")
        self.assertIsNone(superadmin_item["permission_count"])

        role_item = next(item for item in response.data["results"] if not item["is_superadmin"])
        self.assertIn("role", role_item)
        self.assertIn("org", role_item)
        self.assertIn("scope", role_item)
        self.assertIn("permission_count", role_item)
        self.assertEqual(role_item["role"], roles.LIBRARY_ADMIN.external_key)
        self.assertEqual(role_item["org"], "Org1")
        self.assertEqual(role_item["scope"], "lib:Org1:LIB1")
        self.assertGreater(role_item["permission_count"], 0)


@ddt
class TestRoleListView(ViewTestMixin):
    """Test suite for RoleListView."""

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
class TestAssignmentsAPIView(ViewTestMixin):
    """
    Test suite for AssignmentsAPIView.

    Setup summary (from ViewTestMixin.setUpClass):
        lib:Org1:LIB1 → admin_1 (library_admin), regular_1 (library_user), regular_2 (library_user)
        lib:Org2:LIB2 → admin_2 (library_user),  regular_3 (library_user),  regular_4 (library_user)
        lib:Org3:LIB3 → admin_3 (library_admin), regular_5 (library_admin), regular_6 (library_author),
                        regular_7 (library_contributor), regular_8 (library_user)

    URL: /api/authz/v1/assignments/
    Response fields per item: is_superadmin, role, org, scope, permission_count, full_name, username, email

    This endpoint returns one row per (user, assignment) pair — i.e. assignments are
    "unpacked" so each row carries user info alongside the assignment fields.

    Superadmin entries:
        admin_1..3 are staff/superusers. get_superadmin_assignments() (called without
        user_external_keys filter) returns one SuperAdminAssignmentData per superadmin.
        These entries always appear regardless of org/role/scope filters, since those
        filters are applied only to the role assignments fetched separately.

    Total rows when called by a staff user with no filters:
        3 superadmin entries (admin_1, admin_2, admin_3)
        + 11 role assignments (see setup above)
        = 14 rows

    Visibility via get_visible_role_assignments_for_user:
        - Staff/superuser: sees all role assignments across all scopes.
        - regular_1 (library_user in Org1:LIB1): sees only Org1:LIB1 assignments (3).
        - regular_9 (no assignments): sees no role assignments.
        Superadmin entries are always included for all callers.
    """

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.url = reverse("openedx_authz:assignment-list")
        self.get_user_map_patcher = patch(
            "openedx_authz.api.utils.get_user_map",
            side_effect=get_user_map_without_profile,
        )
        self.get_user_map_patcher.start()
        self.addCleanup(self.get_user_map_patcher.stop)

    # -------------------------------------------------------------------- #
    # Visibility: calling user only sees assignments it has view access to #
    # -------------------------------------------------------------------- #

    @data(
        # Staff/superuser sees all: 3 superadmin entries + 11 role assignments = 14
        ("admin_1", status.HTTP_200_OK, 14),
        # regular_1 has LIBRARY_USER in lib:Org1:LIB1 → sees 3 Org1 role assignments + 3 superadmin entries = 6
        ("regular_1", status.HTTP_200_OK, 6),
        # regular_3 has LIBRARY_USER in lib:Org2:LIB2 → sees 3 Org2 role assignments + 3 superadmin entries = 6
        ("regular_3", status.HTTP_200_OK, 6),
        # regular_6 has LIBRARY_AUTHOR in lib:Org3:LIB3 → sees 5 Org3 role assignments + 3 superadmin entries = 8
        ("regular_6", status.HTTP_200_OK, 8),
        # regular_9 has no assignments → 403 (AnyScopePermission requires at least one relevant permission)
        ("regular_9", status.HTTP_403_FORBIDDEN, None),
    )
    @unpack
    def test_visibility_limited_to_accessible_scopes(
        self, username: str, expected_status: int, expected_count: int | None
    ):
        """Calling user only sees role assignments for scopes it has view access to.

        Superadmin entries are always included regardless of the calling user's permissions.
        Users with no VIEW_LIBRARY_TEAM or COURSES_VIEW_COURSE_TEAM permission in any scope
        are rejected with 403 by AnyScopePermission.

        Expected result:
            - Staff/superuser sees all role assignments plus superadmin entries.
            - Regular users see only assignments for their accessible scopes plus superadmin entries.
            - Users with no relevant permissions get 403.
        """
        user = User.objects.get(username=username)
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, expected_status)
        if expected_count is not None:
            self.assertEqual(response.data["count"], expected_count)

    def test_unauthenticated_returns_401(self):
        """Unauthenticated requests are rejected.

        Expected result:
            - Returns 401 UNAUTHORIZED.
        """
        self.client.force_authenticate(user=None)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # ------------------------------------------------------------------ #
    # Filter by orgs                                                     #
    # ------------------------------------------------------------------ #

    @data(
        # Single org: only role assignments in that org + 3 superadmin entries
        ("Org1", 6),  # 3 Org1 role assignments + 3 superadmin entries
        ("Org2", 6),  # 3 Org2 role assignments + 3 superadmin entries
        ("Org3", 8),  # 5 Org3 role assignments + 3 superadmin entries
        # Non-existent org: only superadmin entries
        ("OrgX", 3),
    )
    @unpack
    def test_filter_by_orgs(self, orgs: str, expected_count: int):
        """Results are filtered to the requested orgs.

        Superadmin entries are always included regardless of org filter.

        Expected result:
            - Only role assignments in the given org(s) are returned, plus superadmin entries.
        """
        response = self.client.get(self.url, {"orgs": orgs})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)

    def test_filter_by_multiple_orgs(self):
        """Multiple orgs are OR-combined.

        Expected result:
            - Returns role assignments matching any of the given orgs, plus superadmin entries.
        """
        # Org1 has 3 role assignments, Org2 has 3 → 6 role assignments + 3 superadmin = 9
        response = self.client.get(self.url, {"orgs": "Org1,Org2"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 9)

    # ------------------------------------------------------------------ #
    # Filter by roles                                                    #
    # ------------------------------------------------------------------ #

    @data(
        # library_admin: admin_1 (Org1), admin_3 (Org3), regular_5 (Org3) = 3 + 3 superadmin = 6
        (roles.LIBRARY_ADMIN.external_key, 6),
        # library_user: admin_2 (Org2), regular_1 (Org1), regular_2 (Org1),
        #   regular_3 (Org2), regular_4 (Org2), regular_8 (Org3) = 6 + 3 superadmin = 9
        (roles.LIBRARY_USER.external_key, 9),
        # library_author: regular_6 (Org3) = 1 + 3 superadmin = 4
        (roles.LIBRARY_AUTHOR.external_key, 4),
        # library_contributor: regular_7 (Org3) = 1 + 3 superadmin = 4
        ("library_contributor", 4),
        # Non-existent role: only superadmin entries
        ("non_existent_role", 3),
    )
    @unpack
    def test_filter_by_roles(self, role_filter: str, expected_count: int):
        """Results are filtered to the requested roles.

        Superadmin entries are always included regardless of role filter.

        Expected result:
            - Only role assignments with the given role(s) are returned, plus superadmin entries.
        """
        response = self.client.get(self.url, {"roles": role_filter})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)

    def test_filter_by_multiple_roles(self):
        """Multiple roles are OR-combined.

        Expected result:
            - Returns role assignments matching any of the given roles, plus superadmin entries.
        """
        # library_admin (3) + library_author (1) = 4 role assignments + 3 superadmin = 7
        response = self.client.get(
            self.url,
            {"roles": f"{roles.LIBRARY_ADMIN.external_key},{roles.LIBRARY_AUTHOR.external_key}"},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 7)

    # ------------------------------------------------------------------ #
    # Filter by scopes                                                   #
    # ------------------------------------------------------------------ #

    @data(
        # Single scope
        ("lib:Org1:LIB1", 6),  # 3 Org1 role assignments + 3 superadmin entries
        ("lib:Org2:LIB2", 6),  # 3 Org2 role assignments + 3 superadmin entries
        ("lib:Org3:LIB3", 8),  # 5 Org3 role assignments + 3 superadmin entries
        # Non-existent scope: only superadmin entries
        ("lib:Org99:NOLIB", 3),
    )
    @unpack
    def test_filter_by_scopes(self, scopes: str, expected_count: int):
        """Results are filtered to the requested scopes.

        Superadmin entries are always included regardless of scope filter.

        Expected result:
            - Only role assignments in the given scope(s) are returned, plus superadmin entries.
        """
        response = self.client.get(self.url, {"scopes": scopes})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)

    def test_filter_by_multiple_scopes(self):
        """Multiple scopes are OR-combined.

        Expected result:
            - Returns role assignments matching any of the given scopes, plus superadmin entries.
        """
        # Org1 (3) + Org2 (3) = 6 role assignments + 3 superadmin = 9
        response = self.client.get(self.url, {"scopes": "lib:Org1:LIB1,lib:Org2:LIB2"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 9)

    # ------------------------------------------------------------------ #
    # Search (full_name, username, email)                                #
    # ------------------------------------------------------------------ #

    @data(
        # Exact username match — admin_1 has 1 superadmin entry + 1 role assignment = 2
        ("admin_1", 2),
        # Partial username match — "admin" matches admin_1, admin_2, admin_3
        # Each has 1 superadmin entry + 1 role assignment = 6
        ("admin", 6),
        # Partial username match — "regular" matches regular_1..8 (8 role assignments, no superadmin entries)
        ("regular", 8),
        # Email match
        ("admin_1@example.com", 2),
        # Partial email match — all users have @example.com
        ("@example.com", 14),
        # No match
        ("nonexistent", 0),
    )
    @unpack
    def test_search(self, search: str, expected_count: int):
        """Search filters by full_name, username, or email (case-insensitive).

        Expected result:
            - Returns only assignments whose user's full_name, username, or email
              contains the search term.
        """
        response = self.client.get(self.url, {"search": search})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], expected_count)

    def test_search_case_insensitive(self):
        """Search is case-insensitive.

        Expected result:
            - Uppercase and lowercase search terms return the same results.
        """
        response_lower = self.client.get(self.url, {"search": "admin_1"})
        response_upper = self.client.get(self.url, {"search": "ADMIN_1"})

        self.assertEqual(response_lower.status_code, status.HTTP_200_OK)
        self.assertEqual(response_upper.status_code, status.HTTP_200_OK)
        self.assertEqual(response_lower.data["count"], response_upper.data["count"])

    # ------------------------------------------------------------------ #
    # Sorting                                                            #
    # ------------------------------------------------------------------ #

    @data(
        ("role", "asc"),
        ("role", "desc"),
        ("org", "asc"),
        ("org", "desc"),
        ("scope", "asc"),
        ("scope", "desc"),
        ("full_name", "asc"),
        ("full_name", "desc"),
        ("username", "asc"),
        ("username", "desc"),
        ("email", "asc"),
        ("email", "desc"),
    )
    @unpack
    def test_sorting(self, sort_by: str, order: str):
        """Results can be sorted by role, org, scope, full_name, username, or email.

        Expected result:
            - Returns 200 OK.
            - Results are ordered according to the requested field and direction.
        """
        response = self.client.get(self.url, {"sort_by": sort_by, "order": order})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreater(len(response.data["results"]), 1)
        values = [item[sort_by] for item in response.data["results"]]
        expected = sorted(values, key=lambda v: (v or "").lower(), reverse=order == "desc")
        self.assertEqual(values, expected)

    @data(
        {"sort_by": "invalid"},
        {"sort_by": "permission_count"},
        {"order": "ascending"},
        {"order": "descending"},
    )
    def test_sorting_invalid_params(self, query_params: dict):
        """Invalid sort_by or order values return 400.

        Expected result:
            - Returns 400 BAD REQUEST.
        """
        response = self.client.get(self.url, query_params)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # ------------------------------------------------------------------ #
    # Pagination                                                         #
    # ------------------------------------------------------------------ #

    @data(
        # Total is 14 (3 superadmin + 11 role assignments)
        ({"page": 1, "page_size": 5}, 5, True),
        ({"page": 2, "page_size": 5}, 5, True),
        ({"page": 3, "page_size": 5}, 4, False),
        ({"page": 1, "page_size": 14}, 14, False),
        ({"page": 1, "page_size": 7}, 7, True),
        ({"page": 2, "page_size": 7}, 7, False),
    )
    @unpack
    def test_pagination(self, query_params: dict, expected_page_count: int, has_next: bool):
        """Results are paginated correctly.

        Expected result:
            - Returns 200 OK.
            - Page contains the expected number of items.
            - `next` link is present only when more pages exist.
        """
        response = self.client.get(self.url, query_params)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 14)
        self.assertEqual(len(response.data["results"]), expected_page_count)
        if has_next:
            self.assertIsNotNone(response.data["next"])
        else:
            self.assertIsNone(response.data["next"])

    # ------------------------------------------------------------------ #
    # Response shape                                                     #
    # ------------------------------------------------------------------ #

    def test_response_shape(self):
        """Each result item contains the expected fields.

        Expected result:
            - Returns 200 OK.
            - Each item has is_superadmin, role, org, scope, permission_count,
              full_name, username, and email.
        """
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        expected_fields = {
            "is_superadmin",
            "role",
            "org",
            "scope",
            "permission_count",
            "full_name",
            "username",
            "email",
        }
        for item in response.data["results"]:
            self.assertEqual(set(item.keys()), expected_fields)

    def test_response_shape_superadmin_entry(self):
        """Superadmin entries have the expected field values.

        Expected result:
            - Superadmin entries have role in ("django.superuser", "django.staff"),
              org="*", scope="*", permission_count=None, is_superadmin=True,
              and populated username/email fields.
        """
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        superadmin_items = [item for item in response.data["results"] if item["is_superadmin"]]
        self.assertEqual(len(superadmin_items), 3)
        for item in superadmin_items:
            self.assertIn(item["role"], ("django.superuser", "django.staff"))
            self.assertEqual(item["org"], "*")
            self.assertEqual(item["scope"], "*")
            self.assertIsNone(item["permission_count"])
            self.assertTrue(item["username"])
            self.assertTrue(item["email"])

    def test_response_shape_role_assignment_entry(self):
        """Role assignment entries have the expected field values.

        Expected result:
            - Role assignment entries have is_superadmin=False, concrete role/org/scope
              values, a non-null permission_count, and populated user fields.
        """
        # Filter to a single scope to get predictable results
        response = self.client.get(self.url, {"scopes": "lib:Org1:LIB1"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        role_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        self.assertGreater(len(role_items), 0)
        for item in role_items:
            self.assertFalse(item["is_superadmin"])
            self.assertIn("role", item)
            self.assertEqual(item["org"], "Org1")
            self.assertEqual(item["scope"], "lib:Org1:LIB1")
            self.assertIsNotNone(item["permission_count"])
            self.assertGreater(item["permission_count"], 0)
            self.assertTrue(item["username"])
            self.assertTrue(item["email"])

    # ------------------------------------------------------------------ #
    # Superadmin special cases                                           #
    # ------------------------------------------------------------------ #

    def test_superadmin_entries_always_present(self):
        """Superadmin entries are always included regardless of filters.

        Expected result:
            - Even with a non-matching org filter, superadmin entries are returned.
        """
        response = self.client.get(self.url, {"orgs": "NonExistentOrg"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        superadmin_items = [item for item in response.data["results"] if item["is_superadmin"]]
        self.assertEqual(len(superadmin_items), 3)

    def test_superadmin_entries_not_filtered_by_roles(self):
        """Superadmin entries are not affected by role filters.

        Expected result:
            - Filtering by a specific role still returns all superadmin entries.
        """
        response = self.client.get(self.url, {"roles": roles.LIBRARY_ADMIN.external_key})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        superadmin_items = [item for item in response.data["results"] if item["is_superadmin"]]
        self.assertEqual(len(superadmin_items), 3)

    def test_superadmin_entries_not_filtered_by_scopes(self):
        """Superadmin entries are not affected by scope filters.

        Expected result:
            - Filtering by a specific scope still returns all superadmin entries.
        """
        response = self.client.get(self.url, {"scopes": "lib:Org1:LIB1"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        superadmin_items = [item for item in response.data["results"] if item["is_superadmin"]]
        self.assertEqual(len(superadmin_items), 3)

    def test_superadmin_entries_searchable(self):
        """Superadmin entries are searchable by username.

        Expected result:
            - Searching for a superadmin username returns their entries.
        """
        response = self.client.get(self.url, {"search": "admin_1"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # admin_1 has 1 superadmin entry + 1 role assignment = 2
        self.assertEqual(response.data["count"], 2)
        usernames = {item["username"] for item in response.data["results"]}
        self.assertEqual(usernames, {"admin_1"})

    def test_unprivileged_user_gets_403(self):
        """A user with no relevant permissions is rejected by AnyScopePermission.

        Expected result:
            - Returns 403 FORBIDDEN.
        """
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # ------------------------------------------------------------------ #
    # Combined filters                                                   #
    # ------------------------------------------------------------------ #

    def test_combined_org_and_role_filter(self):
        """Org and role filters can be combined.

        Expected result:
            - Only role assignments matching both the org and role are returned,
              plus superadmin entries.
        """
        # library_admin in Org1 = admin_1 (1 assignment) + 3 superadmin = 4
        response = self.client.get(
            self.url,
            {"orgs": "Org1", "roles": roles.LIBRARY_ADMIN.external_key},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 4)

    def test_combined_scope_and_search(self):
        """Scope filter and search can be combined.

        Expected result:
            - Results are filtered by scope first, then search is applied.
        """
        # Org1 has admin_1, regular_1, regular_2 → 3 role assignments + 3 superadmin = 6
        # Search "regular" matches regular_1, regular_2 → 2 results
        response = self.client.get(
            self.url,
            {"scopes": "lib:Org1:LIB1", "search": "regular"},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 2)


@ddt
class TestAssignmentsAPIViewPermissions(ViewTestMixin):
    """
    Test suite for AssignmentsAPIView calling-user permission scenarios.

    This class extends the base ViewTestMixin setup with course-scope assignments
    to test cross-scope visibility rules.

    Base setup (from ViewTestMixin.setUpClass) — library scopes only:
        lib:Org1:LIB1 → admin_1 (library_admin), regular_1 (library_user), regular_2 (library_user)
        lib:Org2:LIB2 → admin_2 (library_user),  regular_3 (library_user),  regular_4 (library_user)
        lib:Org3:LIB3 → admin_3 (library_admin), regular_5 (library_admin), regular_6 (library_author),
                        regular_7 (library_contributor), regular_8 (library_user)

    Additional course-scope assignments (added in this class):
        course-v1:Org1+COURSE1+2024 → regular_9 (course_staff), regular_10 (course_auditor)

    Permission model:
        - Library scopes require VIEW_LIBRARY_TEAM to be visible.
        - Course scopes require COURSES_VIEW_COURSE_TEAM to be visible.
        - Superadmins (staff/superuser) bypass all permission checks and see everything.
        - Superadmin entries (from get_superadmin_assignments) are always included for all callers.

    Total role assignments after setup:
        11 library assignments + 2 course assignments = 13 role assignments
        + 3 superadmin entries (admin_1, admin_2, admin_3)
        = 16 total rows for a superadmin caller with no filters.
    """

    @classmethod
    def setUpClass(cls):
        """Add course-scope assignments on top of the base library assignments."""
        super().setUpClass()
        cls._assign_roles_to_users(
            [
                {
                    "subject_name": "regular_9",
                    "role_name": roles.COURSE_STAFF.external_key,
                    "scope_name": "course-v1:Org1+COURSE1+2024",
                },
                {
                    "subject_name": "regular_10",
                    "role_name": roles.COURSE_AUDITOR.external_key,
                    "scope_name": "course-v1:Org1+COURSE1+2024",
                },
            ]
        )

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.url = reverse("openedx_authz:assignment-list")
        self.get_user_map_patcher = patch(
            "openedx_authz.api.utils.get_user_map",
            side_effect=get_user_map_without_profile,
        )
        self.get_user_map_patcher.start()
        self.addCleanup(self.get_user_map_patcher.stop)

    # ------------------------------------------------------------------ #
    # Superadmin caller                                                  #
    # ------------------------------------------------------------------ #

    def test_superadmin_sees_all_assignments(self):
        """A superadmin caller sees all role assignments across all scope types.

        admin_1 is staff/superuser → bypasses all permission checks.

        Expected result:
            - Returns 200 OK.
            - Sees all 13 role assignments + 3 superadmin entries = 16 total.
        """
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 16)

    def test_superadmin_sees_library_and_course_assignments(self):
        """A superadmin caller sees both library and course scope assignments.

        Expected result:
            - Response includes assignments with both lib: and course-v1: scope prefixes.
        """
        response = self.client.get(self.url, {"page_size": 100})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        non_superadmin_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        scopes = {item["scope"] for item in non_superadmin_items}
        lib_scopes = {s for s in scopes if s.startswith("lib:")}
        course_scopes = {s for s in scopes if s.startswith("course-v1:")}
        self.assertGreater(len(lib_scopes), 0)
        self.assertGreater(len(course_scopes), 0)

    # ------------------------------------------------------------------ #
    # No permissions at all                                              #
    # ------------------------------------------------------------------ #

    def test_user_without_any_permissions_gets_403(self):
        """A user with no role assignments at all is rejected by AnyScopePermission.

        AnyScopePermission requires the user to have at least one of
        VIEW_LIBRARY_TEAM or COURSES_VIEW_COURSE_TEAM in any scope.
        A user with no assignments has neither, so they get 403.

        Expected result:
            - Returns 403 FORBIDDEN.
        """
        no_perms_user, _ = User.objects.get_or_create(
            username="no_perms_user",
            defaults={"email": "no_perms@example.com"},
        )
        self.client.force_authenticate(user=no_perms_user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # ------------------------------------------------------------------ #
    # Scoped permissions: courses only                                   #
    # ------------------------------------------------------------------ #

    def test_user_with_course_scope_permission_sees_course_assignments(self):
        """A user with COURSES_VIEW_COURSE_TEAM on a specific course sees those assignments.

        regular_9 has course_staff in course-v1:Org1+COURSE1+2024.
        course_staff includes COURSES_VIEW_COURSE_TEAM.

        Expected result:
            - Sees the 2 course assignments in course-v1:Org1+COURSE1+2024
              + 3 superadmin entries = 5 total.
            - Does NOT see any library assignments (no VIEW_LIBRARY_TEAM).
        """
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 5)

        non_superadmin_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        # All non-superadmin items should be course assignments
        for item in non_superadmin_items:
            self.assertTrue(item["scope"].startswith("course-v1:"), f"Expected course scope, got {item['scope']}")

    def test_user_with_course_scope_permission_does_not_see_library_assignments(self):
        """A user with only course permissions cannot see library assignments.

        regular_9 has course_staff in course-v1:Org1+COURSE1+2024 but no library roles.

        Expected result:
            - No library-scope assignments appear in the results.
        """
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        non_superadmin_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        lib_items = [item for item in non_superadmin_items if item["scope"].startswith("lib:")]
        self.assertEqual(len(lib_items), 0)

    # ------------------------------------------------------------------ #
    # Scoped permissions: libraries only                                 #
    # ------------------------------------------------------------------ #

    def test_user_with_library_scope_permission_sees_library_assignments(self):
        """A user with VIEW_LIBRARY_TEAM on a specific library sees those assignments.

        regular_1 has library_user in lib:Org1:LIB1.
        library_user includes VIEW_LIBRARY_TEAM.

        Expected result:
            - Sees the 3 library assignments in lib:Org1:LIB1
              + 3 superadmin entries = 6 total.
            - Does NOT see any course assignments (no COURSES_VIEW_COURSE_TEAM).
        """
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 6)

        non_superadmin_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        # All non-superadmin items should be library assignments
        for item in non_superadmin_items:
            self.assertTrue(item["scope"].startswith("lib:"), f"Expected library scope, got {item['scope']}")

    def test_user_with_library_scope_permission_does_not_see_course_assignments(self):
        """A user with only library permissions cannot see course assignments.

        regular_1 has library_user in lib:Org1:LIB1 but no course roles.

        Expected result:
            - No course-scope assignments appear in the results.
        """
        user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        non_superadmin_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        course_items = [item for item in non_superadmin_items if item["scope"].startswith("course-v1:")]
        self.assertEqual(len(course_items), 0)

    # ------------------------------------------------------------------ #
    # Org-level permissions: courses                                     #
    # ------------------------------------------------------------------ #

    def test_user_with_org_course_permission_sees_org_course_assignments(self):
        """A user with course_staff at org level sees all course assignments in that org.

        Assign regular_10 course_staff at org-level glob course-v1:Org1+* so they
        can see all course assignments in Org1.

        Expected result:
            - Sees course assignments in Org1 + superadmin entries.
            - Does NOT see library assignments.
        """
        self._assign_roles_to_users(
            [
                {
                    "subject_name": "regular_10",
                    "role_name": roles.COURSE_STAFF.external_key,
                    "scope_name": "course-v1:Org1+*",
                },
            ]
        )
        user = User.objects.get(username="regular_10")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        non_superadmin_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        # All non-superadmin items should be course assignments
        for item in non_superadmin_items:
            self.assertTrue(item["scope"].startswith("course-v1:"), f"Expected course scope, got {item['scope']}")
        # Should not see any library assignments
        lib_items = [item for item in non_superadmin_items if item["scope"].startswith("lib:")]
        self.assertEqual(len(lib_items), 0)

    # ------------------------------------------------------------------ #
    # Org-level permissions: libraries                                   #
    # ------------------------------------------------------------------ #

    def test_user_with_org_library_permission_sees_org_library_assignments(self):
        """A user with library_user at org level sees all library assignments in that org.

        Assign regular_9 library_user at org-level glob lib:Org1:* so they
        can see all library assignments in Org1, in addition to their existing
        course assignments.

        Expected result:
            - Sees library assignments in Org1 + course assignments + superadmin entries.
        """
        self._assign_roles_to_users(
            [
                {
                    "subject_name": "regular_9",
                    "role_name": roles.LIBRARY_USER.external_key,
                    "scope_name": "lib:Org1:*",
                },
            ]
        )
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        non_superadmin_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        lib_items = [item for item in non_superadmin_items if item["scope"].startswith("lib:")]
        course_items = [item for item in non_superadmin_items if item["scope"].startswith("course-v1:")]
        # Should see library assignments in Org1 (3 assignments)
        self.assertGreater(len(lib_items), 0)
        for item in lib_items:
            self.assertEqual(item["org"], "Org1")
        # Should also see course assignments (from their existing course_staff role)
        self.assertGreater(len(course_items), 0)

    def test_user_with_org_library_permission_does_not_see_other_org_libraries(self):
        """A user with org-level library permission only sees that org's library assignments.

        Assign regular_9 library_user at org-level glob lib:Org1:* — they should
        NOT see Org2 or Org3 library assignments.

        Expected result:
            - Library assignments are limited to Org1.
        """
        self._assign_roles_to_users(
            [
                {
                    "subject_name": "regular_9",
                    "role_name": roles.LIBRARY_USER.external_key,
                    "scope_name": "lib:Org1:*",
                },
            ]
        )
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        non_superadmin_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        lib_items = [item for item in non_superadmin_items if item["scope"].startswith("lib:")]
        lib_orgs = {item["org"] for item in lib_items}
        self.assertEqual(lib_orgs, {"Org1"})

    # ------------------------------------------------------------------ #
    # Mixed permissions: both library and course                         #
    # ------------------------------------------------------------------ #

    def test_user_with_both_library_and_course_permissions(self):
        """A user with permissions in both library and course scopes sees both.

        Assign regular_9 library_user at lib:Org1:* (in addition to their existing
        course_staff at course-v1:Org1+COURSE1+2024).

        Expected result:
            - Sees both library and course assignments + superadmin entries.
        """
        self._assign_roles_to_users(
            [
                {
                    "subject_name": "regular_9",
                    "role_name": roles.LIBRARY_USER.external_key,
                    "scope_name": "lib:Org1:*",
                },
            ]
        )
        user = User.objects.get(username="regular_9")
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        non_superadmin_items = [item for item in response.data["results"] if not item["is_superadmin"]]
        scope_types = {item["scope"].split(":")[0] for item in non_superadmin_items}
        self.assertIn("lib", scope_types)
        self.assertIn("course-v1", scope_types)
