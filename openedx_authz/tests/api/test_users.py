"""Test suite for user-role assignment API functions."""

from ddt import data, ddt, unpack

from openedx_authz.api.data import ActionData, PermissionData, RoleAssignmentData, RoleData, ScopeData, UserData
from openedx_authz.api.users import *
from openedx_authz.tests.api.test_roles import RolesTestSetupMixin


@ddt
class TestUserRoleAssignments(RolesTestSetupMixin):
    """Test suite for user-role assignment API functions."""

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
                - subject (str): ID of the user namespaced (e.g., 'user:john_doe').
                - role_id (str): Name of the role to assign.
                - scope (str): Scope in which to assign the role.
        """
        if assignments:
            for assignment in assignments:
                assign_role_to_user_in_scope(
                    assignment["subject_name"],
                    assignment["role_name"],
                    assignment["scope_name"],
                )

    @data(
        ("john", "library_admin", "math_101", False),
        ("jane", "library_user", "english_101", False),
        (["mary", "charlie"], "library_collaborator", "science_301", True),
        (["david", "sarah"], "library_author", "history_201", True),
    )
    @unpack
    def test_assign_role_to_user_in_scope(self, username, role, scope_name, batch):
        """Test assigning a role to a user in a specific scope.

        Expected result:
            - The role is successfully assigned to the user in the specified scope.
        """
        if batch:
            batch_assign_role_to_users(users=username, role_name=role, scope=scope_name)
            for user in username:
                user_roles = get_user_role_assignments_in_scope(
                    username=user, scope=scope_name
                )
                role_names = {assignment.role.name for assignment in user_roles}
                self.assertIn(role, role_names)
        else:
            assign_role_to_user_in_scope(
                username=username, role_name=role, scope=scope_name
            )
            user_roles = get_user_role_assignments_in_scope(
                username=username, scope=scope_name
            )
            role_names = {assignment.role.name for assignment in user_roles}
            self.assertIn(role, role_names)

    @data(
        (["Grace"], "library_collaborator", "math_advanced", True),
        (["Liam", "Maya"], "library_author", "art_101", True),
        ("Alice", "library_admin", "math_101", False),
        ("Bob", "library_author", "history_201", False),
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
                users=username, role_name=role, scope=scope_name
            )
            for user in username:
                user_roles = get_user_role_assignments_in_scope(
                    username=user, scope=scope_name
                )
                role_names = {assignment.role.name for assignment in user_roles}
                self.assertNotIn(role, role_names)
        else:
            unassign_role_from_user(user=username, role_name=role, scope=scope_name)
            user_roles = get_user_role_assignments_in_scope(
                username=username, scope=scope_name
            )
            role_names = {assignment.role.name for assignment in user_roles}
            self.assertNotIn(role, role_names)

    @data(
        ("Eve", {"library_admin", "library_author", "library_user"}),
        ("Alice", {"library_admin"}),
        ("Liam", {"library_author"}),
    )
    @unpack
    def test_get_user_role_assignments(self, username, expected_roles):
        """Test retrieving all role assignments for a user across all scopes.

        Expected result:
            - All roles assigned to the user across all scopes are correctly retrieved.
            - Each assigned role is present in the returned role assignments.
        """
        role_assignments = get_user_role_assignments(username=username)
        print(role_assignments)

        assigned_role_names = {assignment.role.name for assignment in role_assignments}
        self.assertEqual(assigned_role_names, expected_roles)

    @data(
        ("Alice", "math_101", {"library_admin"}),
        ("Bob", "history_201", {"library_author"}),
        ("Eve", "physics_401", {"library_admin"}),
        ("Grace", "math_advanced", {"library_collaborator"}),
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
            username=username, scope=scope_name
        )

        role_names = {assignment.role.name for assignment in user_roles}
        self.assertEqual(role_names, expected_roles)

    @data(
        ("library_admin", "math_101", {"alice"}),
        ("library_author", "history_201", {"bob"}),
        ("library_collaborator", "math_advanced", {"grace", "heidi"}),
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
            role_name=role_name, scope=scope_name
        )

        assigned_usernames = {
            assignment.subject.username for assignment in user_assignments
        }

        self.assertEqual(assigned_usernames, expected_users)

    @data(
        (
            "math_101",
            [
                RoleAssignmentData(
                    subject=UserData(username="alice"),
                    role=RoleData(
                        name="library_admin",
                        permissions=[
                            PermissionData(
                                action=ActionData(name="delete_library"), effect="allow"
                            ),
                            PermissionData(
                                action=ActionData(name="publish_library"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(name="manage_library_team"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(name="manage_library_tags"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(name="delete_library_content"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(name="publish_library_content"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(name="delete_library_collection"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(name="create_library"), effect="allow"
                            ),
                            PermissionData(
                                action=ActionData(name="create_library_collection"),
                                effect="allow",
                            ),
                        ],
                    ),
                    scope=ScopeData(name="math_101"),
                ),
            ],
        ),
        (
            "history_201",
            [
                RoleAssignmentData(
                    subject=UserData(username="bob"),
                    role=RoleData(
                        name="library_author",
                        permissions=[
                            PermissionData(
                                action=ActionData(name="delete_library_content"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(name="publish_library_content"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(name="edit_library"), effect="allow"
                            ),
                            PermissionData(
                                action=ActionData(name="manage_library_tags"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(name="create_library_collection"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(name="edit_library_collection"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(name="delete_library_collection"),
                                effect="allow",
                            ),
                        ],
                    ),
                    scope=ScopeData(name="history_201"),
                ),
            ],
        ),
        (
            "physics_401",
            [
                RoleAssignmentData(
                    subject=UserData(username="eve"),
                    role=RoleData(
                        name="library_admin",
                        permissions=[
                            PermissionData(
                                action=ActionData(name="delete_library"), effect="allow"
                            ),
                            PermissionData(
                                action=ActionData(name="publish_library"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(name="manage_library_team"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(name="manage_library_tags"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(name="delete_library_content"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(name="publish_library_content"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(name="delete_library_collection"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(name="create_library"), effect="allow"
                            ),
                            PermissionData(
                                action=ActionData(name="create_library_collection"),
                                effect="allow",
                            ),
                        ],
                    ),
                    scope=ScopeData(name="physics_401"),
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
        role_assignments = get_all_user_role_assignments_in_scope(scope=scope_name)

        self.assertEqual(len(role_assignments), len(expected_assignments))
        for assignment in role_assignments:
            self.assertIn(assignment, expected_assignments)
