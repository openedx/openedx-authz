"""Test suite for user-role assignment API functions."""

from unittest.mock import patch

from ddt import data, ddt, unpack
from django.contrib.auth import get_user_model
from edx_django_utils.cache import RequestCache

from openedx_authz.api.data import ContentLibraryData, RoleAssignmentData, RoleData, UserData
from openedx_authz.api.users import (
    assign_role_to_user_in_scope,
    batch_assign_role_to_users_in_scope,
    batch_unassign_role_from_users,
    get_all_user_role_assignments_in_scope,
    get_user_role_assignments,
    get_user_role_assignments_for_role_in_scope,
    get_user_role_assignments_in_scope,
    get_visible_user_role_assignments_filtered_by_current_user,
    is_user_allowed,
    unassign_all_roles_from_user,
    unassign_role_from_user,
    validate_users,
)
from openedx_authz.constants import permissions, roles
from openedx_authz.constants.roles import LIBRARY_ADMIN_PERMISSIONS, LIBRARY_AUTHOR_PERMISSIONS
from openedx_authz.tests.api.test_roles import RolesTestSetupMixin


class UserAssignmentsSetupMixin(RolesTestSetupMixin):
    """Mixin to set up user-role assignments for testing."""

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
        if assignments:
            for assignment in assignments:
                assign_role_to_user_in_scope(
                    assignment["subject_name"],
                    assignment["role_name"],
                    assignment["scope_name"],
                )


@ddt
class TestUserRoleAssignments(UserAssignmentsSetupMixin):
    """Test suite for user-role assignment API functions."""

    @data(
        ("john", roles.LIBRARY_ADMIN.external_key, "lib:Org1:math_101", False),
        ("jane", roles.LIBRARY_USER.external_key, "lib:Org1:english_101", False),
        (["mary", "charlie"], roles.LIBRARY_CONTRIBUTOR.external_key, "lib:Org1:science_301", True),
        (["david", "sarah"], roles.LIBRARY_AUTHOR.external_key, "lib:Org1:history_201", True),
    )
    @unpack
    def test_assign_role_to_user_in_scope(self, username, role, scope_name, batch):
        """Test assigning a role to a user in a specific scope.

        Expected result:
            - The role is successfully assigned to the user in the specified scope.
        """
        if batch:
            batch_assign_role_to_users_in_scope(users=username, role_external_key=role, scope_external_key=scope_name)
            for user in username:
                user_roles = get_user_role_assignments_in_scope(user_external_key=user, scope_external_key=scope_name)
                role_names = {r.external_key for assignment in user_roles for r in assignment.roles}
                self.assertIn(role, role_names)
        else:
            assign_role_to_user_in_scope(
                user_external_key=username,
                role_external_key=role,
                scope_external_key=scope_name,
            )
            user_roles = get_user_role_assignments_in_scope(user_external_key=username, scope_external_key=scope_name)
            role_names = {r.external_key for assignment in user_roles for r in assignment.roles}
            self.assertIn(role, role_names)

    @data(
        (["grace"], roles.LIBRARY_CONTRIBUTOR.external_key, "lib:Org1:math_advanced", True),
        (["liam", "maya"], roles.LIBRARY_AUTHOR.external_key, "lib:Org4:art_101", True),
        ("alice", roles.LIBRARY_ADMIN.external_key, "lib:Org1:math_101", False),
        ("bob", roles.LIBRARY_AUTHOR.external_key, "lib:Org1:history_201", False),
    )
    @unpack
    def test_unassign_role_from_user(self, username, role, scope_name, batch):
        """Test unassigning a role from a user in a specific scope.

        Expected result:
            - The role is successfully unassigned from the user in the specified scope.
            - The user no longer has the role in the specified scope.
        """
        if batch:
            batch_unassign_role_from_users(users=username, role_external_key=role, scope_external_key=scope_name)
            for user in username:
                user_roles = get_user_role_assignments_in_scope(user_external_key=user, scope_external_key=scope_name)
                role_names = {r.external_key for assignment in user_roles for r in assignment.roles}
                self.assertNotIn(role, role_names)
        else:
            unassign_role_from_user(
                user_external_key=username,
                role_external_key=role,
                scope_external_key=scope_name,
            )
            user_roles = get_user_role_assignments_in_scope(user_external_key=username, scope_external_key=scope_name)
            role_names = {r.external_key for assignment in user_roles for r in assignment.roles}
            self.assertNotIn(role, role_names)

    @data(
        ("eve", {roles.LIBRARY_ADMIN.external_key, roles.LIBRARY_AUTHOR.external_key, roles.LIBRARY_USER.external_key}),
        ("alice", {roles.LIBRARY_ADMIN.external_key}),
        ("liam", {roles.LIBRARY_AUTHOR.external_key}),
    )
    @unpack
    def test_get_user_role_assignments(self, username, expected_roles):
        """Test retrieving all role assignments for a user across all scopes.

        Expected result:
            - All roles assigned to the user across all scopes are correctly retrieved.
            - Each assigned role is present in the returned role assignments.
        """
        role_assignments = get_user_role_assignments(user_external_key=username)

        assigned_role_names = {r.external_key for assignment in role_assignments for r in assignment.roles}
        self.assertEqual(assigned_role_names, expected_roles)

    @data(
        ("alice", "lib:Org1:math_101", {roles.LIBRARY_ADMIN.external_key}),
        ("bob", "lib:Org1:history_201", {roles.LIBRARY_AUTHOR.external_key}),
        ("eve", "lib:Org2:physics_401", {roles.LIBRARY_ADMIN.external_key}),
        ("grace", "lib:Org1:math_advanced", {roles.LIBRARY_CONTRIBUTOR.external_key}),
    )
    @unpack
    def test_get_user_role_assignments_in_scope(self, username, scope_name, expected_roles):
        """Test retrieving role assignments for a user within a specific scope.

        Expected result:
            - The role assigned to the user in the specified scope is correctly retrieved.
            - The returned role assignments contain the assigned role.
        """
        user_roles = get_user_role_assignments_in_scope(user_external_key=username, scope_external_key=scope_name)

        role_names = {r.external_key for assignment in user_roles for r in assignment.roles}
        self.assertEqual(role_names, expected_roles)

    @data(
        (roles.LIBRARY_ADMIN.external_key, "lib:Org1:math_101", {"alice"}),
        (roles.LIBRARY_AUTHOR.external_key, "lib:Org1:history_201", {"bob"}),
        (roles.LIBRARY_CONTRIBUTOR.external_key, "lib:Org1:math_advanced", {"grace", "heidi"}),
    )
    @unpack
    def test_get_user_role_assignments_for_role_in_scope(self, role_name, scope_name, expected_users):
        """Test retrieving all users assigned to a specific role within a specific scope.

        Expected result:
            - All users assigned to the role in the specified scope are correctly retrieved.
            - Each assigned user is present in the returned user assignments.
        """
        user_assignments = get_user_role_assignments_for_role_in_scope(
            role_external_key=role_name, scope_external_key=scope_name
        )

        assigned_usernames = {assignment.subject.username for assignment in user_assignments}

        self.assertEqual(assigned_usernames, expected_users)

    @data(
        (
            "lib:Org1:math_101",
            [
                RoleAssignmentData(
                    subject=UserData(external_key="alice"),
                    roles=[
                        RoleData(
                            external_key=roles.LIBRARY_ADMIN.external_key,
                            permissions=LIBRARY_ADMIN_PERMISSIONS,
                        )
                    ],
                    scope=ContentLibraryData(external_key="lib:Org1:math_101"),
                ),
            ],
        ),
        (
            "lib:Org1:history_201",
            [
                RoleAssignmentData(
                    subject=UserData(external_key="bob"),
                    roles=[
                        RoleData(
                            external_key=roles.LIBRARY_AUTHOR.external_key,
                            permissions=LIBRARY_AUTHOR_PERMISSIONS,
                        )
                    ],
                    scope=ContentLibraryData(external_key="lib:Org1:history_201"),
                ),
            ],
        ),
        (
            "lib:Org2:physics_401",
            [
                RoleAssignmentData(
                    subject=UserData(external_key="eve"),
                    roles=[
                        RoleData(
                            external_key=roles.LIBRARY_ADMIN.external_key,
                            permissions=LIBRARY_ADMIN_PERMISSIONS,
                        )
                    ],
                    scope=ContentLibraryData(external_key="lib:Org2:physics_401"),
                ),
            ],
        ),
    )
    @unpack
    def test_get_all_user_role_assignments_in_scope(self, scope_name, expected_assignments):
        """Test retrieving all user role assignments within a specific scope.

        Expected result:
            - All user role assignments in the specified scope are correctly retrieved.
            - Each assignment includes the subject, role, and scope information.
        """
        role_assignments = get_all_user_role_assignments_in_scope(scope_external_key=scope_name)

        self.assertEqual(len(role_assignments), len(expected_assignments))
        for assignment in role_assignments:
            self.assertIn(assignment, expected_assignments)

    @data(
        # Test user with single role in single scope
        ("alice", ["lib:Org1:math_101"], {"library_admin"}),
        # Test user with multiple roles in different scopes
        (
            "eve",
            ["lib:Org2:physics_401", "lib:Org2:chemistry_501", "lib:Org2:biology_601"],
            {"library_admin", "library_author", "library_user"},
        ),
        # Test user with same role in multiple scopes
        ("liam", ["lib:Org4:art_101", "lib:Org4:art_201", "lib:Org4:art_301"], {"library_author"}),
        # Test user with multiple different roles in multiple scopes
        (
            "peter",
            ["lib:Org6:project_alpha", "lib:Org6:project_beta", "lib:Org6:project_gamma", "lib:Org6:project_delta"],
            {"library_admin", "library_author", "library_contributor", "library_user"},
        ),
    )
    @unpack
    def test_unassign_all_roles_from_user_removes_all_assignments(self, username, scopes, expected_roles_before):
        """Test that unassign_all_roles_from_user removes all role assignments.

        Expected result:
            - Before unassignment: User has roles in specified scopes
            - Function returns True indicating roles were removed
            - After unassignment: User has no role assignments in any scope
            - Querying role assignments returns empty list
        """
        # Verify the user has roles before unassignment
        assignments_before = get_user_role_assignments(user_external_key=username)
        self.assertGreater(len(assignments_before), 0)

        # Verify roles are what we expect before removal
        roles_before = {r.external_key for assignment in assignments_before for r in assignment.roles}
        self.assertEqual(roles_before, expected_roles_before)

        # Verify assignments exist in each expected scope
        for scope_name in scopes:
            scope_assignments = get_user_role_assignments_in_scope(
                user_external_key=username, scope_external_key=scope_name
            )
            self.assertGreater(len(scope_assignments), 0)

        # Unassign all roles from the user
        result = unassign_all_roles_from_user(user_external_key=username)

        # Verify the function returns True (indicating roles were removed)
        self.assertTrue(result)

        # Verify the user has no role assignments after unassignment
        assignments_after = get_user_role_assignments(user_external_key=username)
        self.assertEqual(len(assignments_after), 0)

        # Verify no assignments in any of the previous scopes
        for scope_name in scopes:
            scope_assignments = get_user_role_assignments_in_scope(
                user_external_key=username, scope_external_key=scope_name
            )
            self.assertEqual(len(scope_assignments), 0)

    def test_unassign_all_roles_from_user_with_no_roles_returns_false(self):
        """Test that unassigning a user with no roles returns False.

        Expected result:
            - Function returns False when user has no role assignments
            - No errors occur when trying to unassign from non-existent user
        """
        non_existent_user = "user_with_no_roles"

        # Verify the user has no roles
        assignments_before = get_user_role_assignments(user_external_key=non_existent_user)
        self.assertEqual(len(assignments_before), 0)

        # Unassign all roles (should return False since there are none)
        result = unassign_all_roles_from_user(user_external_key=non_existent_user)

        # Verify the function returns False (no roles to remove)
        self.assertFalse(result)

        # Verify still no assignments after the operation
        assignments_after = get_user_role_assignments(user_external_key=non_existent_user)
        self.assertEqual(len(assignments_after), 0)

    def test_unassign_all_roles_does_not_affect_other_users(self):
        """Test that unassigning one user does not affect other users.

        Expected result:
            - When unassigning roles from one user, other users retain their roles
            - Other users with the same roles in the same scopes are unaffected
        """
        # Use users that share the same scope
        user_to_unassign = "grace"
        other_user = "heidi"
        shared_scope = "lib:Org1:math_advanced"

        # Verify both users have roles in the shared scope before
        grace_assignments_before = get_user_role_assignments_in_scope(
            user_external_key=user_to_unassign, scope_external_key=shared_scope
        )
        heidi_assignments_before = get_user_role_assignments_in_scope(
            user_external_key=other_user, scope_external_key=shared_scope
        )

        self.assertGreater(len(grace_assignments_before), 0)
        self.assertGreater(len(heidi_assignments_before), 0)

        # Unassign all roles from grace
        result = unassign_all_roles_from_user(user_external_key=user_to_unassign)
        self.assertTrue(result)

        # Verify grace has no assignments after unassignment
        grace_assignments_after = get_user_role_assignments(user_external_key=user_to_unassign)
        self.assertEqual(len(grace_assignments_after), 0)

        # Verify heidi still has her assignments
        heidi_assignments_after = get_user_role_assignments_in_scope(
            user_external_key=other_user, scope_external_key=shared_scope
        )
        self.assertEqual(len(heidi_assignments_after), len(heidi_assignments_before))

        # Verify heidi still has the library_contributor role
        heidi_roles = {r.external_key for assignment in heidi_assignments_after for r in assignment.roles}
        self.assertIn("library_contributor", heidi_roles)

    def test_unassign_and_reassign_user(self):
        """Test that a user can be reassigned roles after being unassigned.

        Expected result:
            - User has roles initially
            - After unassignment, user has no roles
            - User can be assigned new roles
            - Newly assigned roles work correctly
        """
        username = "bob"
        new_scope = "lib:Org1:new_library"
        new_role = "library_admin"

        # Verify bob has roles initially
        assignments_before = get_user_role_assignments(user_external_key=username)
        self.assertGreater(len(assignments_before), 0)

        # Unassign all roles
        result = unassign_all_roles_from_user(user_external_key=username)
        self.assertTrue(result)

        # Verify no roles after unassignment
        assignments_after_unassign = get_user_role_assignments(user_external_key=username)
        self.assertEqual(len(assignments_after_unassign), 0)

        # Assign a new role in a new scope
        assign_result = assign_role_to_user_in_scope(
            user_external_key=username, role_external_key=new_role, scope_external_key=new_scope
        )
        self.assertTrue(assign_result)

        # Verify the new assignment works
        new_assignments = get_user_role_assignments_in_scope(user_external_key=username, scope_external_key=new_scope)
        self.assertEqual(len(new_assignments), 1)

        new_roles = {r.external_key for assignment in new_assignments for r in assignment.roles}
        self.assertIn(new_role, new_roles)

    def test_unassign_all_roles_impacts_permissions(self):
        """Test that unassigning all roles removes the user's permissions.

        Expected result:
            - User has permissions before unassignment
            - After unassignment, user no longer has those permissions
            - Permission checks return False after unassignment
        """
        username = "alice"
        scope = "lib:Org1:math_101"
        action = permissions.DELETE_LIBRARY.identifier

        # Verify alice has the permission before unassignment
        has_permission_before = is_user_allowed(
            user_external_key=username,
            action_external_key=action,
            scope_external_key=scope,
        )
        self.assertTrue(has_permission_before)

        # Unassign all roles
        result = unassign_all_roles_from_user(user_external_key=username)
        self.assertTrue(result)

        # Verify alice no longer has the permission
        has_permission_after = is_user_allowed(
            user_external_key=username,
            action_external_key=action,
            scope_external_key=scope,
        )
        self.assertFalse(has_permission_after)


@ddt
class TestUserPermissions(UserAssignmentsSetupMixin):
    """Test suite for user permission API functions."""

    @data(
        # Course permissions
        (
            "daniel",
            permissions.COURSES_MANAGE_ADVANCED_SETTINGS.identifier,
            "course-v1:TestOrg+TestCourse+2024_T1",
            True,
        ),
        (
            "daniel",
            permissions.COURSES_MANAGE_ADVANCED_SETTINGS.identifier,
            "course-v1:TestOrg+TestCourse+2024_T2",
            False,
        ),
        (
            "judy",
            permissions.COURSES_MANAGE_ADVANCED_SETTINGS.identifier,
            "course-v1:TestOrg+TestCourse+2024_T1",
            False,
        ),
        ("judy", permissions.COURSES_MANAGE_ADVANCED_SETTINGS.identifier, "course-v1:TestOrg+TestCourse+2024_T2", True),
        # Multiple subjects with same role in same scope
        (
            "maria",
            permissions.COURSES_MANAGE_ADVANCED_SETTINGS.identifier,
            "course-v1:TestOrg+TestCourse+2024_T3",
            True,
        ),
        ("aida", permissions.COURSES_MANAGE_ADVANCED_SETTINGS.identifier, "course-v1:TestOrg+TestCourse+2024_T3", True),
        (
            "maria",
            permissions.COURSES_MANAGE_ADVANCED_SETTINGS.identifier,
            "course-v1:TestOrg+TestCourse+2024_T1",
            False,
        ),
        (
            "aida",
            permissions.COURSES_MANAGE_ADVANCED_SETTINGS.identifier,
            "course-v1:TestOrg+TestCourse+2024_T1",
            False,
        ),
        # Same user, same role, different scopes
        (
            "carlos",
            permissions.COURSES_MANAGE_ADVANCED_SETTINGS.identifier,
            "course-v1:TestOrg+TestCourse+2024_T1",
            True,
        ),
        (
            "carlos",
            permissions.COURSES_MANAGE_ADVANCED_SETTINGS.identifier,
            "course-v1:TestOrg+TestCourse+2024_T2",
            True,
        ),
        (
            "carlos",
            permissions.COURSES_MANAGE_ADVANCED_SETTINGS.identifier,
            "course-v1:TestOrg+TestCourse+2024_T3",
            True,
        ),
        # Library permissions
        ("alice", permissions.DELETE_LIBRARY.identifier, "lib:Org1:math_101", True),
        ("bob", permissions.PUBLISH_LIBRARY_CONTENT.identifier, "lib:Org1:history_201", True),
        ("eve", permissions.MANAGE_LIBRARY_TEAM.identifier, "lib:Org2:physics_401", True),
        ("grace", permissions.EDIT_LIBRARY_CONTENT.identifier, "lib:Org1:math_advanced", True),
        ("heidi", permissions.CREATE_LIBRARY_COLLECTION.identifier, "lib:Org1:math_advanced", True),
        ("charlie", permissions.DELETE_LIBRARY.identifier, "lib:Org1:science_301", False),
        ("david", permissions.PUBLISH_LIBRARY_CONTENT.identifier, "lib:Org1:history_201", False),
        ("mallory", permissions.MANAGE_LIBRARY_TEAM.identifier, "lib:Org1:math_101", False),
        ("oscar", permissions.EDIT_LIBRARY_CONTENT.identifier, "lib:Org4:art_101", False),
        ("peggy", permissions.CREATE_LIBRARY_COLLECTION.identifier, "lib:Org2:physics_401", False),
    )
    @unpack
    def test_is_user_allowed(self, username, action, scope_name, expected_result):
        """Test checking if a user has a specific permission in a given scope.

        Expected result:
            - The function correctly identifies whether the user has the specified permission in the scope.
        """
        result = is_user_allowed(
            user_external_key=username,
            action_external_key=action,
            scope_external_key=scope_name,
        )
        self.assertEqual(result, expected_result)


class TestIsUserAllowedRequestCache(UserAssignmentsSetupMixin):
    """Test that is_user_allowed uses a per-request cache to avoid redundant enforcement calls."""

    def setUp(self):
        super().setUp()
        # Clear the request cache before each test so results don't bleed across tests.
        RequestCache.clear_all_namespaces()

    def test_cache_hit_on_repeated_call(self):
        """Repeated calls with identical arguments should only invoke the enforcer once."""
        username = "alice"
        action = permissions.DELETE_LIBRARY.identifier
        scope = "lib:Org1:math_101"

        with patch("openedx_authz.api.users.is_subject_allowed") as mock_enforce:
            mock_enforce.return_value = True
            first = is_user_allowed(user_external_key=username, action_external_key=action, scope_external_key=scope)
            second = is_user_allowed(user_external_key=username, action_external_key=action, scope_external_key=scope)

        self.assertTrue(first)
        self.assertEqual(first, second)
        # The underlying enforcement should have been invoked only once; the second call is served from cache.
        self.assertEqual(mock_enforce.call_count, 1)

    def test_cache_miss_on_different_scope(self):
        """Different scope arguments must produce independent cache entries."""
        username = "alice"
        action = permissions.DELETE_LIBRARY.identifier

        with patch("openedx_authz.api.users.is_subject_allowed") as mock_enforce:
            mock_enforce.return_value = True
            is_user_allowed(user_external_key=username, action_external_key=action, scope_external_key="lib:Org1:math_101")
            is_user_allowed(user_external_key=username, action_external_key=action, scope_external_key="lib:Org1:math_advanced")

        # Each distinct scope key is a separate cache entry → two enforcer calls.
        self.assertEqual(mock_enforce.call_count, 2)

    def test_cache_cleared_after_role_mutation(self):
        """The cache must be invalidated when a role assignment changes within the same request."""
        username = "alice"
        action = permissions.DELETE_LIBRARY.identifier
        scope = "lib:Org1:math_101"

        # alice has the permission before unassignment
        before = is_user_allowed(user_external_key=username, action_external_key=action, scope_external_key=scope)
        self.assertTrue(before)

        # Unassigning roles should clear the cache so the next call goes to the enforcer.
        unassign_all_roles_from_user(user_external_key=username)

        after = is_user_allowed(user_external_key=username, action_external_key=action, scope_external_key=scope)
        self.assertFalse(after)


@ddt
class TestValidateUsersAPI(UserAssignmentsSetupMixin):
    """Test suite for validate_users API function - focused on business logic."""

    def test_validate_users_empty_list(self):
        """Test validate_users with empty input list."""
        valid_users, invalid_users = validate_users([])

        self.assertEqual(valid_users, [])
        self.assertEqual(invalid_users, [])

    def test_validate_users_inactive_user_edge_case(self):
        """Test that inactive users are correctly identified as invalid."""
        User = get_user_model()

        # Create an inactive user for this test
        inactive_user = User.objects.create_user(
            username="inactive_api_test", email="inactive_api@example.com", is_active=False
        )

        valid_users, invalid_users = validate_users([inactive_user.username])

        # Cleanup
        inactive_user.delete()

        self.assertEqual(valid_users, [])
        self.assertEqual(invalid_users, [inactive_user.username])

    @patch("openedx_authz.api.users.get_user_by_username_or_email")
    def test_validate_users_unexpected_exception_propagation(self, mock_get_user):
        """Test that unexpected exceptions from get_user_by_username_or_email are re-raised."""
        # Simulate an unexpected database error
        mock_get_user.side_effect = Exception("Database connection lost")

        with self.assertRaises(Exception) as cm:
            validate_users(["any_user"])

        self.assertEqual(str(cm.exception), "Database connection lost")
        mock_get_user.assert_called_once_with("any_user")

    @patch("openedx_authz.api.users.get_user_by_username_or_email")
    def test_validate_users_user_does_not_exist_handling(self, mock_get_user):
        """Test handling of User.DoesNotExist exception."""
        User = get_user_model()
        mock_get_user.side_effect = User.DoesNotExist("User not found")

        valid_users, invalid_users = validate_users(["nonexistent_user"])

        self.assertEqual(valid_users, [])
        self.assertEqual(invalid_users, ["nonexistent_user"])


class TestGetVisibleUserRoleAssignmentsFilteredByCurrentUserActiveFilter(UserAssignmentsSetupMixin):
    """Test that get_visible_user_role_assignments_filtered_by_current_user excludes inactive users."""

    def test_active_user_assignments_are_returned(self):
        """Test that assignments for an active user are returned."""
        User = get_user_model()
        User.objects.create_user(username="alice", email="alice@example.com", is_active=True)

        assignments = get_visible_user_role_assignments_filtered_by_current_user(
            user_external_key="alice",
        )

        usernames = {a.subject.username for a in assignments}
        self.assertIn("alice", usernames)

    def test_inactive_user_assignments_are_excluded(self):
        """Test that assignments for an inactive user are filtered out."""
        User = get_user_model()
        User.objects.create_user(username="alice", email="alice@example.com", is_active=False)

        assignments = get_visible_user_role_assignments_filtered_by_current_user(
            user_external_key="alice",
        )

        self.assertEqual(assignments, [])

    def test_mixed_active_inactive_subjects_in_assignments(self):
        """Test that only active users' assignments are returned when multiple subjects exist."""
        User = get_user_model()
        # eve has roles in lib:Org2:physics_401, lib:Org2:chemistry_501, lib:Org2:biology_601
        # grace has a role in lib:Org1:math_advanced
        User.objects.create_user(username="eve", email="eve@example.com", is_active=True)
        User.objects.create_user(username="grace", email="grace@example.com", is_active=False)

        eve_assignments = get_visible_user_role_assignments_filtered_by_current_user(
            user_external_key="eve",
        )
        grace_assignments = get_visible_user_role_assignments_filtered_by_current_user(
            user_external_key="grace",
        )

        self.assertGreater(len(eve_assignments), 0)
        self.assertEqual(grace_assignments, [])
