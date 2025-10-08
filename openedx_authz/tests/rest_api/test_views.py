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
from rest_framework.test import APITestCase

from openedx_authz import api
from openedx_authz.api.data import ActionData, PermissionData, RoleAssignmentData, RoleData, ScopeData, UserData

User = get_user_model()


class ViewTestMixin(APITestCase):
    """Mixin providing common test utilities for view tests."""

    @staticmethod
    def create_user(username: str, email: str, is_superuser: bool = False, is_staff: bool = False):
        """Create a user with the given data."""
        return User.objects.create_user(
            username=username,
            email=email,
            password="testpass123",
            is_superuser=is_superuser,
            is_staff=is_staff,
        )

    @classmethod
    def setUpTestData(cls):
        """Set up test fixtures once for the entire test class."""
        cls.admin_user = cls.create_user(
            username="admin_user",
            email="admin@example.com",
            is_superuser=True,
            is_staff=True,
        )
        cls.regular_user = cls.create_user(
            username="regular_user",
            email="regular@example.com",
        )
        cls.regular_user2 = cls.create_user(
            username="regular_user2",
            email="regular2@example.com",
        )


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
        ([{"action": "edit_library", "scope": "lib:DemoX:CSPROB"}], [True]),
        # Single permission - denied
        ([{"action": "delete_library", "scope": "lib:DemoX:CSPROB"}], [False]),
        # Multiple permissions - mixed results
        (
            [
                {"action": "edit_library", "scope": "lib:DemoX:CSPROB"},
                {"action": "delete_library_content", "scope": "lib:DemoX:CSPR2"},
            ],
            [True, False],
        ),
    )
    @unpack
    def test_post_permission_validation_success(self, request_data: list[dict], permission_map: list[bool]):
        """Test successful permission validation requests.

        Expected result:
            - Returns 200 OK status
            - Returns correct permission validation results
        """
        expected_response = request_data.copy()
        for idx, perm in enumerate(permission_map):
            expected_response[idx]["allowed"] = perm

        with patch.object(api, "is_user_allowed", side_effect=permission_map) as mock_has_perm:
            response = self.client.post(self.url, data=request_data, format="json")

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data, expected_response)
            self.assertEqual(mock_has_perm.call_count, len(request_data))

    def test_post_permission_validation_invalid_data(self):
        """Test permission validation with invalid request data (missing scope).

        Expected result:
            - Returns 400 BAD REQUEST status
        """
        invalid_data = [{"action": "edit_library"}]

        response = self.client.post(self.url, data=invalid_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_permission_validation_unauthenticated(self):
        """Test permission validation without authentication.

        Expected result:
            - Returns 401 UNAUTHORIZED status
        """
        self.client.force_authenticate(user=None)

        response = self.client.post(
            self.url, data=[{"action": "edit_library", "scope": "lib:DemoX:CSPROB"}], format="json"
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_post_permission_validation_exception_handling(self):
        """Test permission validation when an exception occurs.

        Expected result:
            - Returns 500 INTERNAL SERVER ERROR status
            - Returns empty response data when exceptions occur
        """
        with patch.object(api, "is_user_allowed") as mock_has_perm:
            mock_has_perm.side_effect = Exception("Test exception")

            response = self.client.post(
                self.url, data=[{"action": "edit_library", "scope": "lib:DemoX:CSPROB"}], format="json"
            )

            self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
            self.assertEqual(response.data, {"message": "An error occurred while validating permissions"})

    def test_post_permission_validation_empty_list(self):
        """Test permission validation with empty list.

        Expected result:
            - Returns 200 OK status
            - Returns empty list
        """
        response = self.client.post(self.url, data=[], format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, [])


@ddt
class TestRoleUserAPIView(ViewTestMixin):
    """Test suite for RoleUserAPIView."""

    USERS_DATA = [
        {
            "username": "admin_user",
            "roles": ["library_admin", "library_user"],
        },
        {
            "username": "regular_user",
            "roles": ["library_user"],
        },
        {
            "username": "regular_user2",
            "roles": ["library_author"],
        },
    ]

    @classmethod
    def setUpTestData(cls):
        """Set up test fixtures."""
        super().setUpTestData()

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.client.force_authenticate(user=self.admin_user)
        self.url = reverse("openedx_authz:role-user-list")

    def create_mock_assignments(self, users_data: list[dict], scope: str):
        """Create mock assignments for the given users data."""
        return [
            RoleAssignmentData(
                subject=UserData(external_key=user["username"]),
                roles=[RoleData(external_key=role) for role in user["roles"]],
                scope=ScopeData(external_key=scope),
            )
            for user in users_data
        ]

    @data(
        ({}, 3),
        ({"search": "regular"}, 2),
        ({"search": "regular2"}, 1),
        ({"search": "nonexistent"}, 0),
        ({"roles": "library_admin"}, 1),
        ({"roles": "library_author"}, 1),
        ({"roles": "library_user"}, 2),
        ({"search": "regular", "roles": "library_admin"}, 0),
        ({"search": "regular", "roles": "library_user"}, 1),
        ({"search": "regular", "roles": "library_author"}, 1),
    )
    @unpack
    @patch.object(api, "get_all_user_role_assignments_in_scope")
    def test_get_users_in_role_success(self, query_params: dict, expected_count: int, mock_get_assignments):
        """Test retrieving users with their role assignments in a scope.

        Expected result:
            - Returns 200 OK status
            - Returns correct user role assignments
        """
        scope = "lib:DemoX:CSPROB"
        query_params["scope"] = scope
        mock_assignments = self.create_mock_assignments(self.USERS_DATA, scope)
        mock_get_assignments.return_value = mock_assignments

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
    def test_get_users_in_role_invalid_params(self, query_params: dict):
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
        (None, status.HTTP_401_UNAUTHORIZED, False),
        # Admin user
        ("admin_user", status.HTTP_200_OK, True),
        # Regular user with permission
        ("regular_user", status.HTTP_200_OK, True),
        # Regular user without permission
        ("regular_user", status.HTTP_403_FORBIDDEN, False),
    )
    @unpack
    @patch.object(api, "is_user_allowed")
    def test_get_users_in_role_permissions(
        self,
        username: str,
        status_code: int,
        return_value: bool,
        mock_is_allowed,
    ):
        """Test retrieving users in a role with different user permissions.

        Expected result:
            - Returns appropriate status code based on permissions
        """
        scope = "lib:DemoX:CSPROB"
        mock_is_allowed.return_value = return_value
        user = User.objects.filter(username=username).first()
        self.client.force_authenticate(user=user)

        response = self.client.get(self.url, {"scope": scope})

        self.assertEqual(response.status_code, status_code)
        if user and user.username != "admin_user":
            mock_is_allowed.assert_called_once_with(user.username, "view_library_team", scope)
        else:
            mock_is_allowed.assert_not_called()

    @data(
        # Single user - success (admin user)
        (["admin_user"], 1, 0, [True]),
        # Single user - success (regular user)
        (["regular_user"], 1, 0, [True]),
        # Multiple users - all success
        (["admin_user", "regular_user", "regular_user2"], 3, 0, [True, True, True]),
        # Multiple users - one user already has the role
        (["admin_user", "regular_user", "regular_user2"], 2, 1, [True, True, False]),
        # Multiple users - all users already have the role
        (["admin_user", "regular_user", "regular_user2"], 0, 3, [False, False, False]),
        # Multiple users - mixed results (already has role, user not found, exception)
        (["admin_user", "regular_user", "regular_user2"], 0, 3, [False, User.DoesNotExist(), Exception()]),
        # Multiple users - one user not found
        (["admin_user", "regular_user", "nonexistent"], 2, 1, [True, True, False]),
    )
    @unpack
    @patch.object(api, "assign_role_to_user_in_scope")
    def test_put_add_users_to_role(
        self,
        users: list[str],
        expected_completed: int,
        expected_errors: int,
        mock_assign_role_side_effect: list[bool],
        mock_assign_role,
    ):  # pylint: disable=too-many-positional-arguments
        """Test adding users to a role within a scope.

        Expected result:
            - Returns 207 MULTI-STATUS status
            - Returns appropriate completed and error counts
        """
        request_data = {"role": "library_admin", "scope": "lib:DemoX:CSPROB", "users": users}
        mock_assign_role.side_effect = mock_assign_role_side_effect

        response = self.client.put(self.url, data=request_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
        self.assertEqual(len(response.data["completed"]), expected_completed)
        self.assertEqual(len(response.data["errors"]), expected_errors)

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
    def test_put_add_users_to_role_invalid_data(self, request_data: dict):
        """Test adding users with invalid request data.

        Expected result:
            - Returns 400 BAD REQUEST status
        """
        response = self.client.put(self.url, data=request_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @data(
        # Unauthenticated
        (None, status.HTTP_401_UNAUTHORIZED, False),
        # Admin user
        ("admin_user", status.HTTP_207_MULTI_STATUS, True),
        # Regular user with permission
        ("regular_user", status.HTTP_207_MULTI_STATUS, True),
        # Regular user without permission
        ("regular_user", status.HTTP_403_FORBIDDEN, False),
    )
    @unpack
    @patch.object(api, "is_user_allowed")
    def test_put_add_users_to_role_permissions(
        self,
        username: str,
        status_code: int,
        return_value: bool,
        mock_is_allowed,
    ):
        """Test adding users to role with different permission scenarios.

        Expected result:
            - Returns appropriate status code based on permissions
        """
        scope = "lib:DemoX:CSPROB"
        request_data = {"role": "library_admin", "scope": scope, "users": ["admin_user"]}
        mock_is_allowed.return_value = return_value
        user = User.objects.filter(username=username).first()
        self.client.force_authenticate(user=user)

        response = self.client.put(self.url, data=request_data, format="json")

        self.assertEqual(response.status_code, status_code)
        if user and user.username != "admin_user":
            mock_is_allowed.assert_called_once_with(user.username, "manage_library_team", scope)
        else:
            mock_is_allowed.assert_not_called()

    @data(
        # Single user - success (admin user)
        (["admin_user"], 1, 0, [True]),
        # Single user - success (regular user)
        (["regular_user"], 1, 0, [True]),
        # Multiple users - all success
        (["admin_user", "regular_user", "regular_user2"], 3, 0, [True, True, True]),
        # Multiple users - one user does not have the role
        (["admin_user", "regular_user", "regular_user2"], 2, 1, [True, True, False]),
        # Multiple users - all users do not have the role
        (["admin_user", "regular_user", "regular_user2"], 0, 3, [False, False, False]),
        # Multiple users - mixed results (no role, user not found, exception)
        (["admin_user", "regular_user", "regular_user2"], 0, 3, [False, User.DoesNotExist(), Exception()]),
        # Multiple users - one user not found
        (["admin_user", "regular_user", "nonexistent"], 2, 1, [True, True, False]),
    )
    @unpack
    @patch.object(api, "unassign_role_from_user")
    def test_delete_remove_users_from_role(
        self,
        users: list[str],
        expected_completed: int,
        expected_errors: int,
        mock_unassign_role_side_effect: list[bool],
        mock_unassign_role,
    ):  # pylint: disable=too-many-positional-arguments
        """Test removing users from a role within a scope.

        Expected result:
            - Returns 207 MULTI-STATUS status
            - Returns appropriate completed and error counts
        """
        query_params = {
            "role": "library_admin",
            "scope": "lib:DemoX:CSPROB",
            "users": ",".join(users),
        }
        mock_unassign_role.side_effect = mock_unassign_role_side_effect

        response = self.client.delete(f"{self.url}?{urlencode(query_params)}")

        self.assertEqual(response.status_code, status.HTTP_207_MULTI_STATUS)
        self.assertEqual(len(response.data["completed"]), expected_completed)
        self.assertEqual(len(response.data["errors"]), expected_errors)

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
    def test_delete_remove_users_from_role_invalid_params(self, query_params: dict):
        """Test removing users with invalid query parameters.

        Expected result:
            - Returns 400 BAD REQUEST status
        """
        response = self.client.delete(f"{self.url}?{urlencode(query_params)}")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @data(
        # Unauthenticated
        (None, status.HTTP_401_UNAUTHORIZED, False),
        # Admin user
        ("admin_user", status.HTTP_207_MULTI_STATUS, True),
        # Regular user with permission
        ("regular_user", status.HTTP_207_MULTI_STATUS, True),
        # Regular user without permission
        ("regular_user", status.HTTP_403_FORBIDDEN, False),
    )
    @unpack
    @patch.object(api, "is_user_allowed")
    def test_delete_remove_users_from_role_permissions(
        self,
        username: str,
        status_code: int,
        return_value: bool,
        mock_is_allowed,
    ):
        """Test removing users from role with different permission scenarios.

        Expected result:
            - Returns appropriate status code based on permissions
        """
        scope = "lib:DemoX:CSPROB"
        query_params = {"role": "library_admin", "scope": scope, "users": "admin_user"}
        mock_is_allowed.return_value = return_value
        user = User.objects.filter(username=username).first()
        self.client.force_authenticate(user=user)

        response = self.client.delete(f"{self.url}?{urlencode(query_params)}")

        self.assertEqual(response.status_code, status_code)
        if user and user.username != "admin_user":
            mock_is_allowed.assert_called_once_with(user.username, "manage_library_team", scope)
        else:
            mock_is_allowed.assert_not_called()


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

    def create_mock_roles(self, roles: list[dict]):
        """Create mock roles."""
        return [
            RoleData(
                external_key=role["role"],
                permissions=[PermissionData(action=ActionData(external_key=perm)) for perm in role["permissions"]],
            )
            for role in roles
        ]

    @patch.object(api, "get_users_for_role")
    @patch.object(api, "get_role_definitions_in_scope")
    def test_get_roles_success(self, mock_get_roles, mock_get_users):
        """Test retrieving role definitions and their permissions.

        Expected result:
            - Returns 200 OK status
            - Returns correct role definitions with permissions and user counts
        """
        mock_roles = self.create_mock_roles(
            [
                {"role": "library_admin", "permissions": ["delete_library", "manage_library_team"]},
                {"role": "library_author", "permissions": ["delete_library_content", "publish_library_content"]},
                {"role": "library_user", "permissions": ["view_library", "view_library_team"]},
            ]
        )
        mock_get_roles.return_value = mock_roles
        mock_get_users.side_effect = [
            [UserData(external_key="user1"), UserData(external_key="user2")],
            [UserData(external_key="user3")],
            [UserData(external_key="user4")],
        ]

        response = self.client.get(self.url, {"scope": "lib^*"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)

        self.assertEqual(len(response.data["results"]), len(mock_roles))
        first_role = response.data["results"][0]
        self.assertEqual(first_role["role"], "library_admin")
        self.assertIn("delete_library", first_role["permissions"])
        self.assertIn("manage_library_team", first_role["permissions"])
        self.assertEqual(first_role["user_count"], 2)

        second_role = response.data["results"][1]
        self.assertEqual(second_role["role"], "library_author")
        self.assertIn("delete_library_content", second_role["permissions"])
        self.assertIn("publish_library_content", second_role["permissions"])
        self.assertEqual(second_role["user_count"], 1)

        third_role = response.data["results"][2]
        self.assertEqual(third_role["role"], "library_user")
        self.assertIn("view_library", third_role["permissions"])
        self.assertIn("view_library_team", third_role["permissions"])
        self.assertEqual(third_role["user_count"], 1)

    @patch.object(api, "get_role_definitions_in_scope")
    def test_get_roles_empty_result(self, mock_get_roles):
        """Test retrieving roles when none exist in scope.

        Expected result:
            - Returns 200 OK status
            - Returns empty results list
        """
        mock_get_roles.return_value = []

        response = self.client.get(self.url, {"scope": "lib^*"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertEqual(len(response.data["results"]), 0)

    @data(
        {},
        {"scope": ""},
        {"scope": "a" * 256},
    )
    def test_get_roles_invalid_scope(self, query_params: dict):
        """Test retrieving roles without required scope parameter.

        Expected result:
            - Returns 400 BAD REQUEST status
        """
        response = self.client.get(self.url, query_params)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch.object(api, "get_users_for_role")
    @patch.object(api, "get_role_definitions_in_scope")
    def test_get_roles_pagination(self, mock_get_roles, mock_get_users):
        """Test retrieving roles with pagination.

        Expected result:
            - Returns 200 OK status
            - Returns paginated results with correct page size
        """
        mock_roles = [
            RoleData(
                external_key=f"role_{i}",
                permissions=[
                    PermissionData(action=ActionData(external_key=f"action_{i}"), effect="allow"),
                ],
            )
            for i in range(15)
        ]
        mock_get_roles.return_value = mock_roles
        mock_get_users.return_value = []

        response = self.client.get(self.url, {"scope": "lib^*", "page": 1, "page_size": 10})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertEqual(len(response.data["results"]), 10)
        self.assertIn("next", response.data)
        self.assertIsNotNone(response.data["next"])
