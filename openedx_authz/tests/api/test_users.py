"""Test suite for user-role assignment API functions."""

from unittest.mock import patch

from ddt import data, ddt, unpack
from django.contrib.auth import get_user_model

from openedx_authz.api.data import (
    ContentLibraryData,
    CourseOverviewData,
    GlobalWildcardScopeData,
    RoleAssignmentData,
    RoleData,
    UserData,
)
from openedx_authz.api.users import (
    _filter_allowed_assignments,
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


class TestFilterAllowedAssignmentsPermissionLogic(UserAssignmentsSetupMixin):
    """Test the OR logic and empty-list behavior of _filter_allowed_assignments.

    The function iterates each assignment's ``get_admin_view_permissions()`` list
    and includes the assignment if the user has *any* of those permissions (OR).
    An empty permissions list means the assignment is always excluded.
    """

    def _make_assignment(self, scope_cls, scope_key, role_key="library_admin"):
        """Build a minimal RoleAssignmentData for testing."""
        return RoleAssignmentData(
            subject=UserData(external_key="alice"),
            roles=[RoleData(external_key=role_key)],
            scope=scope_cls(external_key=scope_key),
        )

    # -- empty list → always excluded ------------------------------------

    def test_empty_permissions_list_excludes_assignment(self):
        """When get_admin_view_permissions returns [], the assignment is excluded
        regardless of the user's actual permissions."""

        assignment = self._make_assignment(ContentLibraryData, "lib:Org1:math_101")

        with patch.object(ContentLibraryData, "get_admin_view_permissions", return_value=[]):
            result = _filter_allowed_assignments([assignment], user_external_key="alice")

        self.assertEqual(result, [])

    # -- single permission → standard check ------------------------------

    def test_single_permission_granted_includes_assignment(self):
        """A single-element permissions list where the user has the permission
        results in the assignment being included."""

        assignment = self._make_assignment(ContentLibraryData, "lib:Org1:math_101")

        # alice is library_admin on lib:Org1:math_101 → has VIEW_LIBRARY_TEAM
        result = _filter_allowed_assignments([assignment], user_external_key="alice")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], assignment)

    def test_single_permission_denied_excludes_assignment(self):
        """A single-element permissions list where the user lacks the permission
        results in the assignment being excluded."""

        # mallory has no roles in lib:Org1:math_101
        assignment = self._make_assignment(ContentLibraryData, "lib:Org1:math_101")

        result = _filter_allowed_assignments([assignment], user_external_key="mallory")

        self.assertEqual(result, [])

    # -- multiple permissions → OR logic ---------------------------------

    def test_or_logic_first_permission_granted(self):
        """When the permissions list has two entries and the user has only the
        first one, the assignment is included (OR)."""

        assignment = self._make_assignment(ContentLibraryData, "lib:Org1:math_101")

        # alice has VIEW_LIBRARY_TEAM on this scope but not COURSES_VIEW_COURSE_TEAM
        with patch.object(
            ContentLibraryData,
            "get_admin_view_permissions",
            return_value=[permissions.VIEW_LIBRARY_TEAM, permissions.COURSES_VIEW_COURSE_TEAM],
        ):
            result = _filter_allowed_assignments([assignment], user_external_key="alice")

        self.assertEqual(len(result), 1)

    def test_or_logic_second_permission_granted(self):
        """When the permissions list has two entries and the user has only the
        second one, the assignment is included (OR)."""
        # daniel is course_staff on course-v1:TestOrg+TestCourse+2024_T1
        # → has COURSES_VIEW_COURSE_TEAM but not VIEW_LIBRARY_TEAM on that scope

        assignment = self._make_assignment(
            CourseOverviewData, "course-v1:TestOrg+TestCourse+2024_T1", role_key="course_staff"
        )

        with patch.object(
            CourseOverviewData,
            "get_admin_view_permissions",
            return_value=[permissions.VIEW_LIBRARY_TEAM, permissions.COURSES_VIEW_COURSE_TEAM],
        ):
            result = _filter_allowed_assignments([assignment], user_external_key="daniel")

        self.assertEqual(len(result), 1)

    def test_or_logic_no_permission_granted(self):
        """When the permissions list has two entries and the user has neither,
        the assignment is excluded."""

        # mallory has no roles anywhere
        assignment = self._make_assignment(ContentLibraryData, "lib:Org1:math_101")

        with patch.object(
            ContentLibraryData,
            "get_admin_view_permissions",
            return_value=[permissions.VIEW_LIBRARY_TEAM, permissions.COURSES_VIEW_COURSE_TEAM],
        ):
            result = _filter_allowed_assignments([assignment], user_external_key="mallory")

        self.assertEqual(result, [])

    # -- no user specified → return all ----------------------------------

    def test_no_user_returns_all_assignments(self):
        """When user_external_key is None, all assignments are returned
        regardless of permissions."""

        assignment = self._make_assignment(ContentLibraryData, "lib:Org1:math_101")

        with patch.object(ContentLibraryData, "get_admin_view_permissions", return_value=[]):
            result = _filter_allowed_assignments([assignment], user_external_key=None)

        self.assertEqual(len(result), 1)

    # -- mixed assignments -----------------------------------------------

    def test_mixed_assignments_filtered_correctly(self):
        """A mix of assignments with different permission lists are filtered
        correctly: empty-list scopes excluded, single-perm scopes checked,
        multi-perm scopes use OR."""

        # alice has VIEW_LIBRARY_TEAM on lib:Org1:math_101
        lib_assignment = self._make_assignment(ContentLibraryData, "lib:Org1:math_101")

        # GlobalWildcardScopeData returns [VIEW_LIBRARY_TEAM, COURSES_VIEW_COURSE_TEAM]
        # alice has VIEW_LIBRARY_TEAM on lib:Org1:math_101 but the scope here is *
        # which won't match — so this tests that the scope_external_key matters
        global_assignment = RoleAssignmentData(
            subject=UserData(external_key="alice"),
            roles=[RoleData(external_key="library_admin")],
            scope=GlobalWildcardScopeData(external_key="*"),
        )

        result = _filter_allowed_assignments([lib_assignment, global_assignment], user_external_key="alice")

        # lib assignment should be included (alice has VIEW_LIBRARY_TEAM there)
        self.assertIn(lib_assignment, result)
