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
from openedx_authz.rest_api.enums import RoleOperationError, RoleOperationStatus
from openedx_authz.tests.api.test_users import UserAssignmentsSetupMixin

User = get_user_model()


def get_user_map_without_profile(usernames: list[str]) -> dict[str, User]:
    """
    Test version of get_user_map that doesn't use select_related('profile').

    The generic Django User model doesn't have a profile relation,
    so we override this in tests to avoid FieldError.
    """
    users = User.objects.filter(username__in=usernames)
    return {user.username: user for user in users}


class ViewTestMixin(UserAssignmentsSetupMixin):
    """Mixin providing common test utilities for view tests."""

    @classmethod
    def setUpTestData(cls):
        """Set up test fixtures once for the entire test class."""
        super().setUpTestData()
        # Users with assigned roles
        cls.admin_user = User.objects.create_superuser(
            username="alice",
            email="alice@example.com",
        )
        cls.regular_user = User.objects.create_user(
            username="bob",
            email="bob@example.com",
        )
        cls.regular_user2 = User.objects.create_user(
            username="carol",
            email="carol@example.com",
        )
        cls.regular_user3 = User.objects.create_user(
            username="ivy",
            email="ivy@example.com",
        )
        cls.regular_user4 = User.objects.create_user(
            username="jack",
            email="jack@example.com",
        )
        cls.regular_user5 = User.objects.create_user(
            username="kate",
            email="kate@example.com",
        )
        # Users without assigned roles
        cls.regular_user7 = User.objects.create_user(
            username="zoey",
            email="zoey@example.com",
        )

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.client = APIClient()


@ddt
class TestPermissionValidationMeView(ViewTestMixin):
    """Test suite for PermissionValidationMeView."""

    @classmethod
    def setUpTestData(cls):
        """Set up test fixtures."""
        super().setUpTestData()

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.client.force_authenticate(user=self.admin_user)
        self.url = reverse("openedx_authz:permission-validation-me")

    @data(
        # Single permission - allowed
        ([{"action": "view_library", "scope": "lib:Org1:math_101"}], [True]),
        # Single permission - denied (invalid scope)
        ([{"action": "view_library", "scope": "lib:DemoX:CSPROB"}], [False]),
        # Single permission - denied (invalid action)
        ([{"action": "edit_library", "scope": "lib:Org1:math_101"}], [False]),
        # Multiple permissions - mixed results
        (
            [
                {"action": "view_library", "scope": "lib:Org1:math_101"},
                {"action": "view_library", "scope": "lib:DemoX:CSPROB"},
                {"action": "edit_library", "scope": "lib:Org1:math_101"},
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
        expected_response = request_data.copy()
        for idx, perm in enumerate(permission_map):
            expected_response[idx]["allowed"] = perm

        response = self.client.post(self.url, data=request_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, expected_response)

    @data(
        # Single permission
        [{"action": "edit_library"}],
        [{"scope": "lib:Org1:math_101"}],
        [{"action": "edit_library", "scope": ""}],
        [{"action": "edit_library", "scope": "s" * 256}],
        [{"action": "", "scope": "lib:Org1:math_101"}],
        [{"action": "a" * 256, "scope": "lib:Org1:math_101"}],
        # Multiple permissions
        [{}, {}],
        [{}, {"action": "edit_library", "scope": "lib:Org1:math_101"}],
        [{"action": "edit_library", "scope": "lib:Org1:math_101"}, {}],
        [{"action": "edit_library", "scope": "lib:Org1:math_101"}, {"action": "", "scope": "lib:Org1:math_101"}],
        [{"action": "edit_library", "scope": "lib:Org1:math_101"}, {"action": "edit_library", "scope": ""}],
        [{"action": "edit_library", "scope": "lib:Org1:math_101"}, {"scope": "lib:Org1:math_101"}],
        [{"action": "edit_library", "scope": "lib:Org1:math_101"}, {"action": "edit_library"}],
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
        scope = "lib:DemoX:CSPROB"
        self.client.force_authenticate(user=None)

        response = self.client.post(self.url, data=[{"action": action, "scope": scope}], format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch.object(api, "is_user_allowed")
    def test_permission_validation_exception_handling(self, mock_is_user_allowed):
        """Test permission validation when an exception occurs.

        Expected result:
            - Returns 500 INTERNAL SERVER ERROR status
            - Returns empty response data when exceptions occur
        """
        action = "edit_library"
        scope = "lib:DemoX:CSPROB"
        mock_is_user_allowed.side_effect = Exception()

        response = self.client.post(self.url, data=[{"action": action, "scope": scope}], format="json")

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data, {"message": "An error occurred while validating permissions"})


@ddt
class TestRoleUserAPIView(ViewTestMixin):
    """Test suite for RoleUserAPIView."""

    @classmethod
    def setUpTestData(cls):
        """Set up test fixtures."""
        super().setUpTestData()

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
        ({"search": "ivy"}, 1),
        ({"search": "k"}, 2),
        ({"search": "nonexistent"}, 0),
        ({"search": "nonexistent"}, 0),
        # Search by email
        ({"search": "ivy@example.com"}, 1),
        ({"search": "@example.com"}, 3),
        ({"search": "nonexistent@example.com"}, 0),
        # Search by single role
        ({"roles": "library_admin"}, 1),
        ({"roles": "library_author"}, 1),
        ({"roles": "library_user"}, 1),
        # Search by multiple roles
        ({"roles": "library_admin,library_author"}, 2),
        ({"roles": "library_author,library_user"}, 2),
        ({"roles": "library_user,library_admin"}, 2),
        ({"roles": "library_admin,library_author,library_user"}, 3),
        # Search by role and username
        ({"search": "ivy", "roles": "library_admin"}, 1),
        ({"search": "jack", "roles": "library_admin"}, 0),
        # Search by role and email
        ({"search": "ivy@example.com", "roles": "library_admin"}, 1),
        ({"search": "@example.com", "roles": "library_admin"}, 1),
        ({"search": "jack@example.com", "roles": "library_admin"}, 0),
    )
    @unpack
    def test_get_users_by_scope_success(self, query_params: dict, expected_count: int):
        """Test retrieving users with their role assignments in a scope.

        Expected result:
            - Returns 200 OK status
            - Returns correct user role assignments
        """
        query_params["scope"] = "lib:Org3:cs_101"

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
        {"scope": "lib:DemoX:CSPROB", "sort_by": "invalid"},
        {"scope": "lib:DemoX:CSPROB", "sort_by": "name"},
        {"scope": "lib:DemoX:CSPROB", "order": "ascending"},
        {"scope": "lib:DemoX:CSPROB", "order": "descending"},
        {"scope": "lib:DemoX:CSPROB", "order": "up"},
        {"scope": "lib:DemoX:CSPROB", "order": "down"},
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
        ("alice", status.HTTP_200_OK),
        # Regular user with permission
        ("kate", status.HTTP_200_OK),
        # Regular user without permission
        ("zoey", status.HTTP_403_FORBIDDEN),
    )
    @unpack
    def test_get_users_by_scope_permissions(self, username: str, status_code: int):
        """Test retrieving users in a role with different user permissions.

        Expected result:
            - Returns appropriate status code based on permissions
        """
        user = User.objects.filter(username=username).first()
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url, {"scope": "lib:Org3:cs_101"})

        self.assertEqual(response.status_code, status_code)

    @data(
        # With username -----------------------------
        # Single user - success (admin user)
        (["alice"], 1, 0),
        # Single user - success (regular user)
        (["bob"], 1, 0),
        # Multiple users - success (admin and regular users)
        (["alice", "bob", "carol"], 3, 0),
        # With email ---------------------------------
        # Single user - success (admin user)
        (["alice@example.com"], 1, 0),
        # Single user - success (regular user)
        (["bob@example.com"], 1, 0),
        # Multiple users - admin and regular users
        (["alice@example.com", "bob@example.com", "carol@example.com"], 3, 0),
        # With username and email --------------------
        # All success
        (["alice", "bob@example.com", "carol@example.com"], 3, 0),
        # Mixed results (user not found)
        (["alice", "bob@example.com", "nonexistent", "notexistent@example.com"], 2, 2),
    )
    @unpack
    def test_add_users_to_role_success(self, users: list[str], expected_completed: int, expected_errors: int):
        """Test adding users to a role within a scope.

        Expected result:
            - Returns 207 MULTI-STATUS status
            - Returns appropriate completed and error counts
        """
        role = "library_admin"
        request_data = {"role": role, "scope": "lib:DemoX:CSPROB", "users": users}

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.put(self.url, data=request_data, format="json")

            self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
            self.assertEqual(len(response.data["completed"]), expected_completed)
            self.assertEqual(len(response.data["errors"]), expected_errors)

    @data(
        # Single user - success (admin user)
        (["alice"], 0, 1),
        # Single user - success (regular user)
        (["bob"], 0, 1),
        # Multiple users - success
        (["kate", "ivy", "jack"], 3, 0),
        # Multiple users - one user already has the role
        (["alice", "ivy", "jack"], 2, 1),
        # Multiple users - all users already have the role
        (["alice", "bob", "carol"], 0, 3),
    )
    @unpack
    def test_add_users_to_role_already_has_role(self, users: list[str], expected_completed: int, expected_errors: int):
        """Test adding users to a role that already has the role."""
        role = "library_admin"
        scope = "lib:DemoX:CSPROB"
        request_data = {"role": role, "scope": scope, "users": users}
        assignments = [
            {"subject_name": "alice", "role_name": role, "scope_name": scope},
            {"subject_name": "bob", "role_name": role, "scope_name": scope},
            {"subject_name": "carol", "role_name": role, "scope_name": scope},
        ]
        self._assign_roles_to_users(assignments=assignments)

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.put(self.url, data=request_data, format="json")

            self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
            self.assertEqual(len(response.data["completed"]), expected_completed)
            self.assertEqual(len(response.data["errors"]), expected_errors)

    @patch.object(api, "assign_role_to_user_in_scope")
    def test_add_users_to_role_exception_handling(self, mock_assign_role_to_user_in_scope):
        """Test adding users to a role with exception handling."""
        request_data = {"role": "library_admin", "scope": "lib:DemoX:CSPROB", "users": ["alice"]}
        mock_assign_role_to_user_in_scope.side_effect = Exception()

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.put(self.url, data=request_data, format="json")

            self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
            self.assertEqual(len(response.data["completed"]), 0)
            self.assertEqual(len(response.data["errors"]), 1)
            self.assertEqual(response.data["errors"][0]["user_identifier"], "alice")
            self.assertEqual(response.data["errors"][0]["error"], RoleOperationError.ROLE_ASSIGNMENT_ERROR)

    @data(
        {},
        {"role": "library_admin"},
        {"scope": "lib:DemoX:CSPROB"},
        {"users": ["admin_user"]},
        {"role": "library_admin", "scope": "lib:DemoX:CSPROB"},
        {"scope": "lib:DemoX:CSPROB", "users": ["admin_user"]},
        {"users": ["admin_user", "regular_user"], "role": "library_admin"},
        {"role": "library_admin", "scope": "lib:DemoX:CSPROB", "users": []},
        {"role": "", "scope": "lib:DemoX:CSPROB", "users": ["admin_user"]},
        {"role": "library_admin", "scope": "", "users": ["admin_user"]},
    )
    def test_add_users_to_role_invalid_data(self, request_data: dict):
        """Test adding users with invalid request data.

        Expected result:
            - Returns 400 BAD REQUEST status
        """
        response = self.client.put(self.url, data=request_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @data(
        # Unauthenticated
        (None, status.HTTP_401_UNAUTHORIZED),
        # Admin user
        ("alice", status.HTTP_207_MULTI_STATUS),
        # Regular user with permission
        ("ivy", status.HTTP_207_MULTI_STATUS),
        # Regular user without permission
        ("zoey", status.HTTP_403_FORBIDDEN),
    )
    @unpack
    def test_add_users_to_role_permissions(self, username: str, status_code: int):
        """Test adding users to role with different permission scenarios.

        Expected result:
            - Returns appropriate status code based on permissions
        """
        request_data = {"role": "library_admin", "scope": "lib:Org3:cs_101", "users": ["user1"]}
        user = User.objects.filter(username=username).first()
        self.client.force_authenticate(user=user)

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.put(self.url, data=request_data, format="json")

            self.assertEqual(response.status_code, status_code)

    @data(
        # With username -----------------------------
        # Single user - success (admin user)
        (["alice"], 1, 0),
        # Single user - success (regular user)
        (["bob"], 1, 0),
        # Multiple users - all success (admin and regular users)
        (["alice", "bob", "carol"], 3, 0),
        # With email --------------------------------
        # Single user - success (admin user)
        (["alice@example.com"], 1, 0),
        # Single user - success (regular user)
        (["bob@example.com"], 1, 0),
        # Multiple users - all success (admin and regular users)
        (["alice@example.com", "bob@example.com", "carol@example.com"], 3, 0),
        # With username and email -------------------
        # All success
        (["alice", "bob@example.com", "carol@example.com"], 3, 0),
        # Mixed results (user not found)
        (["alice", "bob@example.com", "nonexistent", "notexistent@example.com"], 2, 2),
    )
    @unpack
    def test_remove_users_from_role_success(self, users: list[str], expected_completed: int, expected_errors: int):
        """Test removing users from a role within a scope.

        Expected result:
            - Returns 207 MULTI-STATUS status
            - Returns appropriate completed and error counts
        """
        role = "library_admin"
        scope = "lib:DemoX:CSPROB"
        users_to_assign = ["alice", "bob", "carol"]
        assignments = [{"subject_name": user, "role_name": role, "scope_name": scope} for user in users_to_assign]
        self._assign_roles_to_users(assignments=assignments)
        query_params = {"role": role, "scope": scope, "users": ",".join(users)}

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.delete(f"{self.url}?{urlencode(query_params)}")

            self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
            self.assertEqual(len(response.data["completed"]), expected_completed)
            self.assertEqual(len(response.data["errors"]), expected_errors)

    @patch.object(api, "unassign_role_from_user")
    def test_remove_users_from_role_exception_handling(self, mock_unassign_role_from_user):
        """Test removing users from a role with exception handling."""
        query_params = {"role": "library_admin", "scope": "lib:DemoX:CSPROB", "users": "alice,bob,carol"}
        mock_unassign_role_from_user.side_effect = [True, False, Exception()]

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.delete(f"{self.url}?{urlencode(query_params)}")
            self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
            self.assertEqual(len(response.data["completed"]), 1)
            self.assertEqual(len(response.data["errors"]), 2)
            self.assertEqual(response.data["completed"][0]["user_identifier"], "alice")
            self.assertEqual(response.data["completed"][0]["status"], RoleOperationStatus.ROLE_REMOVED)
            self.assertEqual(response.data["errors"][0]["user_identifier"], "bob")
            self.assertEqual(response.data["errors"][0]["error"], RoleOperationError.USER_DOES_NOT_HAVE_ROLE)
            self.assertEqual(response.data["errors"][1]["user_identifier"], "carol")
            self.assertEqual(response.data["errors"][1]["error"], RoleOperationError.ROLE_REMOVAL_ERROR)

    @data(
        {},
        {"role": "library_admin"},
        {"scope": "lib:DemoX:CSPROB"},
        {"users": "admin_user"},
        {"role": "library_admin", "scope": "lib:DemoX:CSPROB"},
        {"scope": "lib:DemoX:CSPROB", "users": "admin_user"},
        {"users": "admin_user,regular_user", "role": "library_admin"},
        {"role": "library_admin", "scope": "lib:DemoX:CSPROB", "users": ""},
        {"role": "", "scope": "lib:DemoX:CSPROB", "users": "admin_user"},
        {"role": "library_admin", "scope": "", "users": "admin_user"},
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
        ("alice", status.HTTP_207_MULTI_STATUS),
        # Regular user with permission
        ("ivy", status.HTTP_207_MULTI_STATUS),
        # Regular user without permission
        ("zoey", status.HTTP_403_FORBIDDEN),
    )
    @unpack
    def test_remove_users_from_role_permissions(self, username: str, status_code: int):
        """Test removing users from role with different permission scenarios.

        Expected result:
            - Returns appropriate status code based on permissions
        """
        query_params = {"role": "library_admin", "scope": "lib:Org3:cs_101", "users": "user1,user2"}
        user = User.objects.filter(username=username).first()
        self.client.force_authenticate(user=user)

        with patch.object(api.ContentLibraryData, "exists", return_value=True):
            response = self.client.delete(f"{self.url}?{urlencode(query_params)}")

            self.assertEqual(response.status_code, status_code)


@ddt
class TestRoleListView(ViewTestMixin):
    """Test suite for RoleListView."""

    @classmethod
    def setUpTestData(cls):
        """Set up test fixtures."""
        super().setUpTestData()

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
        response = self.client.get(self.url, {"scope": "*"})

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

        response = self.client.get(self.url, {"scope": "*"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertIn("count", response.data)
        self.assertEqual(response.data["count"], 0)
        self.assertEqual(len(response.data["results"]), 0)

    @data(
        {},
        {"scope": ""},
        {"scope": "a" * 256},
    )
    def test_get_roles_invalid_params(self, query_params: dict):
        """Test retrieving roles with invalid query parameters.

        Expected result:
            - Returns 400 BAD REQUEST status
        """
        response = self.client.get(self.url, query_params)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

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
        query_params["scope"] = "*"
        response = self.client.get(self.url, query_params)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertEqual(len(response.data["results"]), expected_count)
        self.assertIn("next", response.data)
        if has_next:
            self.assertIsNotNone(response.data["next"])
        else:
            self.assertIsNone(response.data["next"])
