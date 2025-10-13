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
from openedx_authz.api.users import assign_role_to_user_in_scope
from openedx_authz.rest_api.data import RoleOperationError, RoleOperationStatus
from openedx_authz.rest_api.v1.permissions import DynamicScopePermission
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
    def _assign_roles_to_users(
        cls,
        assignments: list[dict] | None = None,
    ):
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
                "role_name": "library_admin",
                "scope_name": "lib:Org1:LIB1",
            },
            {
                "subject_name": "admin_2",
                "role_name": "library_user",
                "scope_name": "lib:Org2:LIB2",
            },
            {
                "subject_name": "admin_3",
                "role_name": "library_admin",
                "scope_name": "lib:Org3:LIB3",
            },
            # Assign roles to regular users
            {
                "subject_name": "regular_1",
                "role_name": "library_user",
                "scope_name": "lib:Org1:LIB1",
            },
            {
                "subject_name": "regular_2",
                "role_name": "library_user",
                "scope_name": "lib:Org1:LIB1",
            },
            {
                "subject_name": "regular_3",
                "role_name": "library_user",
                "scope_name": "lib:Org2:LIB2",
            },
            {
                "subject_name": "regular_4",
                "role_name": "library_user",
                "scope_name": "lib:Org2:LIB2",
            },
            {
                "subject_name": "regular_5",
                "role_name": "library_admin",
                "scope_name": "lib:Org3:LIB3",
            },
        ]
        cls._assign_roles_to_users(assignments=assignments)

    @classmethod
    def create_regular_users(cls, quantity: int):
        """Create regular users."""
        for i in range(1, quantity + 1):
            User.objects.create_user(username=f"regular_{i}", email=f"regular_{i}@example.com")

    @classmethod
    def create_admin_users(cls, quantity: int):
        """Create admin users."""
        for i in range(1, quantity + 1):
            User.objects.create_superuser(username=f"admin_{i}", email=f"admin_{i}@example.com")

    @classmethod
    def setUpTestData(cls):
        """Set up test fixtures once for the entire test class."""
        super().setUpTestData()
        cls.create_admin_users(quantity=3)
        cls.create_regular_users(quantity=7)

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
        ([{"action": "view_library", "scope": "lib:Org1:LIB1"}], [True]),
        # Single permission - denied (scope not assigned to user)
        ([{"action": "view_library", "scope": "lib:Org2:LIB2"}], [False]),
        # # Single permission - denied (action not assigned to user)
        ([{"action": "edit_library", "scope": "lib:Org1:LIB1"}], [False]),
        # # Multiple permissions - mixed results
        (
            [
                {"action": "view_library", "scope": "lib:Org1:LIB1"},
                {"action": "view_library", "scope": "lib:Org2:LIB2"},
                {"action": "edit_library", "scope": "lib:Org1:LIB1"},
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
        [{"action": "edit_library", "scope": "lib:Org1:LIB1"}, {"action": "", "scope": "lib:Org1:LIB1"}],
        [{"action": "edit_library", "scope": "lib:Org1:LIB1"}, {"action": "edit_library", "scope": ""}],
        [{"action": "edit_library", "scope": "lib:Org1:LIB1"}, {"scope": "lib:Org1:LIB1"}],
        [{"action": "edit_library", "scope": "lib:Org1:LIB1"}, {"action": "edit_library"}],
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
        (Exception(), status.HTTP_500_INTERNAL_SERVER_ERROR, "An error occurred while validating permissions"),
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
                self.url, data=[{"action": "edit_library", "scope": "lib:Org1:LIB1"}], format="json"
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
        ({"roles": "library_admin"}, 1),
        ({"roles": "library_author"}, 0),
        ({"roles": "library_user"}, 2),
        # Search by multiple roles
        ({"roles": "library_admin,library_author"}, 1),
        ({"roles": "library_author,library_user"}, 2),
        ({"roles": "library_user,library_admin"}, 3),
        ({"roles": "library_admin,library_author,library_user"}, 3),
        # Search by role and username
        ({"search": "admin_1", "roles": "library_admin"}, 1),
        ({"search": "regular_1", "roles": "library_user"}, 1),
        ({"search": "regular_1", "roles": "library_admin"}, 0),
        # Search by role and email
        ({"search": "admin_1@example.com", "roles": "library_admin"}, 1),
        ({"search": "@example.com", "roles": "library_admin"}, 1),
        ({"search": "@example.com", "roles": "library_user"}, 2),
        ({"search": "regular_1@example.com", "roles": "library_admin"}, 0),
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
        (["admin_1@example.com", "regular_1@example.com", "regular_2@example.com"], 3, 0),
        # With username and email --------------------
        # All success
        (["admin_1", "regular_1@example.com", "regular_2@example.com"], 3, 0),
        # Mixed results (user not found)
        (["admin_1", "regular_1@example.com", "nonexistent", "notexistent@example.com"], 2, 2),
    )
    @unpack
    def test_add_users_to_role_success(self, users: list[str], expected_completed: int, expected_errors: int):
        """Test adding users to a role within a scope.

        Expected result:
            - Returns 207 MULTI-STATUS status
            - Returns appropriate completed and error counts
        """
        role = "library_admin"
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
        role = "library_user"
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
        request_data = {"role": "library_admin", "scope": "lib:Org1:LIB1", "users": ["regular_1"]}
        mock_assign_role_to_user_in_scope.side_effect = Exception()

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.put(self.url, data=request_data, format="json")

            self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
            self.assertEqual(len(response.data["completed"]), 0)
            self.assertEqual(len(response.data["errors"]), 1)
            self.assertEqual(response.data["errors"][0]["user_identifier"], "regular_1")
            self.assertEqual(response.data["errors"][0]["error"], RoleOperationError.ROLE_ASSIGNMENT_ERROR)

    @data(
        {},
        {"role": "library_admin"},
        {"scope": "lib:Org1:LIB1"},
        {"users": ["admin_1"]},
        {"role": "library_admin", "scope": "lib:Org1:LIB1"},
        {"scope": "lib:Org1:LIB1", "users": ["admin_1"]},
        {"users": ["admin_1", "regular_1"], "role": "library_admin"},
        {"role": "library_admin", "scope": "lib:Org1:LIB1", "users": []},
        {"role": "", "scope": "lib:Org1:LIB1", "users": ["admin_1"]},
        {"role": "library_admin", "scope": "", "users": ["admin_1"]},
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
        request_data = {"role": "library_admin", "scope": "lib:Org3:LIB3", "users": ["regular_2"]}
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
        (["admin_2@example.com", "regular_3@example.com", "regular_4@example.com"], 3, 0),
        # With username and email -------------------
        # All success
        (["admin_2", "regular_3@example.com", "regular_4@example.com"], 3, 0),
        # Mixed results (user not found)
        (["admin_2", "regular_3@example.com", "nonexistent", "notexistent@example.com"], 2, 2),
    )
    @unpack
    def test_remove_users_from_role_success(self, users: list[str], expected_completed: int, expected_errors: int):
        """Test removing users from a role within a scope.

        Expected result:
            - Returns 207 MULTI-STATUS status
            - Returns appropriate completed and error counts
        """
        query_params = {"role": "library_user", "scope": "lib:Org2:LIB2", "users": ",".join(users)}

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.delete(f"{self.url}?{urlencode(query_params)}")

            self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
            self.assertEqual(len(response.data["completed"]), expected_completed)
            self.assertEqual(len(response.data["errors"]), expected_errors)

    @patch.object(api, "unassign_role_from_user")
    def test_remove_users_from_role_exception_handling(self, mock_unassign_role_from_user):
        """Test removing users from a role with exception handling."""
        query_params = {"role": "library_admin", "scope": "lib:Org1:LIB1", "users": "regular_1,regular_2,regular_3"}
        mock_unassign_role_from_user.side_effect = [True, False, Exception()]

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.delete(f"{self.url}?{urlencode(query_params)}")
            self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
            self.assertEqual(len(response.data["completed"]), 1)
            self.assertEqual(len(response.data["errors"]), 2)
            self.assertEqual(response.data["completed"][0]["user_identifier"], "regular_1")
            self.assertEqual(response.data["completed"][0]["status"], RoleOperationStatus.ROLE_REMOVED)
            self.assertEqual(response.data["errors"][0]["user_identifier"], "regular_2")
            self.assertEqual(response.data["errors"][0]["error"], RoleOperationError.USER_DOES_NOT_HAVE_ROLE)
            self.assertEqual(response.data["errors"][1]["user_identifier"], "regular_3")
            self.assertEqual(response.data["errors"][1]["error"], RoleOperationError.ROLE_REMOVAL_ERROR)

    @data(
        {},
        {"role": "library_admin"},
        {"scope": "lib:Org1:LIB1"},
        {"users": "admin_1"},
        {"role": "library_admin", "scope": "lib:Org1:LIB1"},
        {"scope": "lib:Org1:LIB1", "users": "admin_1"},
        {"users": "admin_1,regular_1", "role": "library_admin"},
        {"role": "library_admin", "scope": "lib:Org1:LIB1", "users": ""},
        {"role": "", "scope": "lib:Org1:LIB1", "users": "admin_1"},
        {"role": "library_admin", "scope": "", "users": "admin_1"},
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
        query_params = {"role": "library_admin", "scope": "lib:Org3:LIB3", "users": "user1,user2"}
        user = User.objects.filter(username=username).first()
        self.client.force_authenticate(user=user)

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.delete(f"{self.url}?{urlencode(query_params)}")

            self.assertEqual(response.status_code, status_code)


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
