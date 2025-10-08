"""Test suite for user-role assignment API functions."""

from ddt import data, ddt, unpack

from openedx_authz.api.data import (
    ActionData,
    ContentLibraryData,
    PermissionData,
    RoleAssignmentData,
    RoleData,
    UserData,
)
from openedx_authz.api.users import (
    assign_role_to_user_in_scope,
    batch_assign_role_to_users_in_scope,
    batch_unassign_role_from_users,
    get_all_user_role_assignments_in_scope,
    get_user_role_assignments,
    get_user_role_assignments_for_role_in_scope,
    get_user_role_assignments_in_scope,
    is_user_allowed,
    unassign_role_from_user,
)
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
        ("john", "library_admin", "lib:Org1:math_101", False),
        ("jane", "library_user", "lib:Org1:english_101", False),
        (["mary", "charlie"], "library_collaborator", "lib:Org1:science_301", True),
        (["david", "sarah"], "library_author", "lib:Org1:history_201", True),
    )
    @unpack
    def test_assign_role_to_user_in_scope(self, username, role, scope_name, batch):
        """Test assigning a role to a user in a specific scope.

        Expected result:
            - The role is successfully assigned to the user in the specified scope.
        """
        if batch:
            batch_assign_role_to_users_in_scope(
                users=username, role_external_key=role, scope_external_key=scope_name
            )
            for user in username:
                user_roles = get_user_role_assignments_in_scope(
                    user_external_key=user, scope_external_key=scope_name
                )
                role_names = {r.external_key for assignment in user_roles for r in assignment.roles}
                self.assertIn(role, role_names)
        else:
            assign_role_to_user_in_scope(
                user_external_key=username,
                role_external_key=role,
                scope_external_key=scope_name,
            )
            user_roles = get_user_role_assignments_in_scope(
                user_external_key=username, scope_external_key=scope_name
            )
            role_names = {r.external_key for assignment in user_roles for r in assignment.roles}
            self.assertIn(role, role_names)

    @data(
        (["grace"], "library_collaborator", "lib:Org1:math_advanced", True),
        (["liam", "maya"], "library_author", "lib:Org4:art_101", True),
        ("alice", "library_admin", "lib:Org1:math_101", False),
        ("bob", "library_author", "lib:Org1:history_201", False),
    )
    @unpack
    def test_unassign_role_from_user(self, username, role, scope_name, batch):
        """Test unassigning a role from a user in a specific scope.

        Expected result:
            - The role is successfully unassigned from the user in the specified scope.
            - The user no longer has the role in the specified scope.
        """
        if batch:
            batch_unassign_role_from_users(
                users=username, role_external_key=role, scope_external_key=scope_name
            )
            for user in username:
                user_roles = get_user_role_assignments_in_scope(
                    user_external_key=user, scope_external_key=scope_name
                )
                role_names = {r.external_key for assignment in user_roles for r in assignment.roles}
                self.assertNotIn(role, role_names)
        else:
            unassign_role_from_user(
                user_external_key=username,
                role_external_key=role,
                scope_external_key=scope_name,
            )
            user_roles = get_user_role_assignments_in_scope(
                user_external_key=username, scope_external_key=scope_name
            )
            role_names = {r.external_key for assignment in user_roles for r in assignment.roles}
            self.assertNotIn(role, role_names)

    @data(
        ("eve", {"library_admin", "library_author", "library_user"}),
        ("alice", {"library_admin"}),
        ("liam", {"library_author"}),
    )
    @unpack
    def test_get_user_role_assignments(self, username, expected_roles):
        """Test retrieving all role assignments for a user across all scopes.

        Expected result:
            - All roles assigned to the user across all scopes are correctly retrieved.
            - Each assigned role is present in the returned role assignments.
        """
        role_assignments = get_user_role_assignments(user_external_key=username)

        assigned_role_names = {
            r.external_key for assignment in role_assignments for r in assignment.roles
        }
        self.assertEqual(assigned_role_names, expected_roles)

    @data(
        ("alice", "lib:Org1:math_101", {"library_admin"}),
        ("bob", "lib:Org1:history_201", {"library_author"}),
        ("eve", "lib:Org2:physics_401", {"library_admin"}),
        ("grace", "lib:Org1:math_advanced", {"library_collaborator"}),
    )
    @unpack
    def test_get_user_role_assignments_in_scope(
        self, username, scope_name, expected_roles
    ):
        """Test retrieving role assignments for a user within a specific scope.

        Expected result:
            - The role assigned to the user in the specified scope is correctly retrieved.
            - The returned role assignments contain the assigned role.
        """
        user_roles = get_user_role_assignments_in_scope(
            user_external_key=username, scope_external_key=scope_name
        )

        role_names = {r.external_key for assignment in user_roles for r in assignment.roles}
        self.assertEqual(role_names, expected_roles)

    @data(
        ("library_admin", "lib:Org1:math_101", {"alice"}),
        ("library_author", "lib:Org1:history_201", {"bob"}),
        ("library_collaborator", "lib:Org1:math_advanced", {"grace", "heidi"}),
    )
    @unpack
    def test_get_user_role_assignments_for_role_in_scope(
        self, role_name, scope_name, expected_users
    ):
        """Test retrieving all users assigned to a specific role within a specific scope.

        Expected result:
            - All users assigned to the role in the specified scope are correctly retrieved.
            - Each assigned user is present in the returned user assignments.
        """
        user_assignments = get_user_role_assignments_for_role_in_scope(
            role_external_key=role_name, scope_external_key=scope_name
        )

        assigned_usernames = {
            assignment.subject.username for assignment in user_assignments
        }

        self.assertEqual(assigned_usernames, expected_users)

    @data(
        (
            "lib:Org1:math_101",
            [
                RoleAssignmentData(
                    subject=UserData(external_key="alice"),
                    roles=[RoleData(
                        external_key="library_admin",
                        permissions=[
                            PermissionData(
                                action=ActionData(external_key="delete_library"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(external_key="publish_library"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(external_key="manage_library_team"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(external_key="manage_library_tags"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(
                                    external_key="delete_library_content"
                                ),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(
                                    external_key="publish_library_content"
                                ),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(
                                    external_key="delete_library_collection"
                                ),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(external_key="create_library"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(
                                    external_key="create_library_collection"
                                ),
                                effect="allow",
                            ),
                        ],
                    )],
                    scope=ContentLibraryData(external_key="lib:Org1:math_101"),
                ),
            ],
        ),
        (
            "lib:Org1:history_201",
            [
                RoleAssignmentData(
                    subject=UserData(external_key="bob"),
                    roles=[RoleData(
                        external_key="library_author",
                        permissions=[
                            PermissionData(
                                action=ActionData(
                                    external_key="delete_library_content"
                                ),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(
                                    external_key="publish_library_content"
                                ),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(external_key="edit_library"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(external_key="manage_library_tags"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(
                                    external_key="create_library_collection"
                                ),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(
                                    external_key="edit_library_collection"
                                ),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(
                                    external_key="delete_library_collection"
                                ),
                                effect="allow",
                            ),
                        ],
                    )],
                    scope=ContentLibraryData(external_key="lib:Org1:history_201"),
                ),
            ],
        ),
        (
            "lib:Org2:physics_401",
            [
                RoleAssignmentData(
                    subject=UserData(external_key="eve"),
                    roles=[RoleData(
                        external_key="library_admin",
                        permissions=[
                            PermissionData(
                                action=ActionData(external_key="delete_library"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(external_key="publish_library"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(external_key="manage_library_team"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(external_key="manage_library_tags"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(
                                    external_key="delete_library_content"
                                ),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(
                                    external_key="publish_library_content"
                                ),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(
                                    external_key="delete_library_collection"
                                ),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(external_key="create_library"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(
                                    external_key="create_library_collection"
                                ),
                                effect="allow",
                            ),
                        ],
                    )],
                    scope=ContentLibraryData(external_key="lib:Org2:physics_401"),
                ),
            ],
        ),
    )
    @unpack
    def test_get_all_user_role_assignments_in_scope(
        self, scope_name, expected_assignments
    ):
        """Test retrieving all user role assignments within a specific scope.

        Expected result:
            - All user role assignments in the specified scope are correctly retrieved.
            - Each assignment includes the subject, role, and scope information.
        """
        role_assignments = get_all_user_role_assignments_in_scope(
            scope_external_key=scope_name
        )

        self.assertEqual(len(role_assignments), len(expected_assignments))
        for assignment in role_assignments:
            self.assertIn(assignment, expected_assignments)


@ddt
class TestUserPermissions(UserAssignmentsSetupMixin):
    """Test suite for user permission API functions."""

    @data(
        ("alice", "delete_library", "lib:Org1:math_101", True),
        ("bob", "publish_library_content", "lib:Org1:history_201", True),
        ("eve", "manage_library_team", "lib:Org2:physics_401", True),
        ("grace", "edit_library", "lib:Org1:math_advanced", True),
        ("heidi", "create_library_collection", "lib:Org1:math_advanced", True),
        ("charlie", "delete_library", "lib:Org1:science_301", False),
        ("david", "publish_library_content", "lib:Org1:history_201", False),
        ("mallory", "manage_library_team", "lib:Org1:math_101", False),
        ("oscar", "edit_library", "lib:Org4:art_101", False),
        ("peggy", "create_library_collection", "lib:Org2:physics_401", False),
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
