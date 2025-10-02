"""Test cases for roles API functions.

In this test suite, we will verify the functionality of the roles API,
including role creation, assignment, permission management, and querying
roles and permissions within specific scopes.
"""

import casbin
from ddt import data as ddt_data
from ddt import ddt, unpack
from django.test import TestCase

from openedx_authz.api import *
from openedx_authz.api.data import (
    ActionData,
    ContentLibraryData,
    PermissionData,
    RoleData,
    ScopeData,
    SubjectData,
)
from openedx_authz.engine.enforcer import enforcer as global_enforcer
from openedx_authz.engine.utils import migrate_policy_from_file_to_db


class RolesTestSetupMixin(TestCase):
    """Mixin to set up roles and assignments for tests."""

    @classmethod
    def _seed_database_with_policies(cls):
        """Seed the database with policies from the policy file.

        This simulates the one-time database seeding that would happen
        during application deployment, separate from the runtime policy loading.
        """
        global_enforcer.load_policy()
        migrate_policy_from_file_to_db(
            source_enforcer=casbin.Enforcer(
                "openedx_authz/engine/config/model.conf",
                "openedx_authz/engine/config/authz.policy",
            ),
            target_enforcer=global_enforcer,
        )
        global_enforcer.clear_policy()  # Clear to simulate fresh start for each test

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
                assign_role_to_subject_in_scope(
                    subject=SubjectData(
                        name=assignment["subject_name"],
                    ),
                    role=RoleData(name=assignment["role_name"]),
                    scope=ScopeData(name=assignment["scope_name"]),
                )

    @classmethod
    def setUpClass(cls):
        """Set up test class environment."""
        super().setUpClass()
        # Ensure the database is seeded once for all tests in this class
        assignments = [
            # Basic library roles from authz.policy
            {
                "subject_name": "Alice",
                "role_name": "library_admin",
                "scope_name": "math_101",
            },
            {
                "subject_name": "Bob",
                "role_name": "library_author",
                "scope_name": "history_201",
            },
            {
                "subject_name": "Carol",
                "role_name": "library_collaborator",
                "scope_name": "science_301",
            },
            {
                "subject_name": "Dave",
                "role_name": "library_user",
                "scope_name": "english_101",
            },
            # Multi-role assignments - same user with different roles in different libraries
            {
                "subject_name": "Eve",
                "role_name": "library_admin",
                "scope_name": "physics_401",
            },
            {
                "subject_name": "Eve",
                "role_name": "library_author",
                "scope_name": "chemistry_501",
            },
            {
                "subject_name": "Eve",
                "role_name": "library_user",
                "scope_name": "biology_601",
            },
            # Multiple users with same role in same scope_id
            {
                "subject_name": "Grace",
                "role_name": "library_collaborator",
                "scope_name": "math_advanced",
            },
            {
                "subject_name": "Heidi",
                "role_name": "library_collaborator",
                "scope_name": "math_advanced",
            },
            # Hierarchical scope_id assignments - different specificity levels
            {
                "subject_name": "Ivy",
                "role_name": "library_admin",
                "scope_name": "cs_101",
            },
            {
                "subject_name": "Jack",
                "role_name": "library_author",
                "scope_name": "cs_101",
            },
            {
                "subject_name": "Kate",
                "role_name": "library_user",
                "scope_name": "cs_101",
            },
            # Edge case: same user, same role, different scopes
            {
                "subject_name": "Liam",
                "role_name": "library_author",
                "scope_name": "art_101",
            },
            {
                "subject_name": "Liam",
                "role_name": "library_author",
                "scope_name": "art_201",
            },
            {
                "subject_name": "Liam",
                "role_name": "library_author",
                "scope_name": "art_301",
            },
            # Mixed permission levels across libraries for comprehensive testing
            {
                "subject_name": "Maya",
                "role_name": "library_admin",
                "scope_name": "economics_101",
            },
            {
                "subject_name": "Noah",
                "role_name": "library_collaborator",
                "scope_name": "economics_101",
            },
            {
                "subject_name": "Olivia",
                "role_name": "library_user",
                "scope_name": "economics_101",
            },
            # Complex multi-library, multi-role scenario
            {
                "subject_name": "Peter",
                "role_name": "library_admin",
                "scope_name": "project_alpha",
            },
            {
                "subject_name": "Peter",
                "role_name": "library_author",
                "scope_name": "project_beta",
            },
            {
                "subject_name": "Peter",
                "role_name": "library_collaborator",
                "scope_name": "project_gamma",
            },
            {
                "subject_name": "Peter",
                "role_name": "library_user",
                "scope_name": "project_delta",
            },
            {
                "subject_name": "Frank",
                "role_name": "library_user",
                "scope_name": "project_epsilon",
            },
        ]
        cls._seed_database_with_policies()
        cls._assign_roles_to_users(assignments=assignments)

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        global_enforcer.load_policy()  # Load policies before each test to simulate fresh start

    def tearDown(self):
        """Clean up after each test to ensure isolation."""
        super().tearDown()
        global_enforcer.clear_policy()  # Clear policies after each test to ensure isolation


@ddt
class TestRolesAPI(RolesTestSetupMixin):
    """Test cases for roles API functions.

    The enforcer used in these tests cases is the default global enforcer
    instance from `openedx_authz.engine.enforcer` automatically used by
    the API to ensure consistency across tests and production environments.

    In case a different enforcer configuration is needed, consider mocking the
    enforcer instance in the `openedx_authz.api.roles` module.

    These test cases depend on the roles and assignments set up in the
    `RolesTestSetupMixin` class. This means:
    - The database is seeded once per test class with a predefined set of roles
    - Each test runs with a (in-memory) clean state, loading the same set of policies
    - Tests are isolated from each other to prevent state leakage
    - The global enforcer instance is used to ensure consistency with production
    environments.
    """

    @ddt_data(
        # Library Admin role with actual permissions from authz.policy
        (
            "library_admin",
            {
                "library_admin": {
                    "permissions": [
                        PermissionData(
                            action=ActionData(name="delete_library"),
                            effect="allow",
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
                            action=ActionData(name="create_library"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(name="create_library_collection"),
                            effect="allow",
                        ),
                    ],
                }
            },
        ),
        # Library Author role with actual permissions from authz.policy
        (
            "library_author",
            {
                "library_author": {
                    "permissions": [
                        PermissionData(
                            action=ActionData(name="delete_library_content"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(name="publish_library_content"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(name="edit_library"),
                            effect="allow",
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
                }
            },
        ),
        # Library Collaborator role with actual permissions from authz.policy
        (
            "library_collaborator",
            {
                "library_collaborator": {
                    "permissions": [
                        PermissionData(
                            action=ActionData(name="edit_library"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(name="delete_library_content"),
                            effect="allow",
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
                }
            },
        ),
        # Library User role with minimal permissions
        (
            "library_user",
            {
                "library_user": {
                    "permissions": [
                        PermissionData(
                            action=ActionData(name="view_library"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(name="view_library_team"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(name="reuse_library_content"),
                            effect="allow",
                        ),
                    ],
                }
            },
        ),
        # Role in different scope for multi-role user (eve) - this user IS assigned this role in this scope
        (
            "library_admin",
            {
                "library_admin": {
                    "permissions": [
                        PermissionData(
                            action=ActionData(name="delete_library"),
                            effect="allow",
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
                            action=ActionData(name="create_library"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(name="create_library_collection"),
                            effect="allow",
                        ),
                    ],
                }
            },
        ),
        # Non-existent role
        (
            "non_existent_role",
            {"non_existent_role": {"permissions": []}},
        ),
        # Empty role list
        # ("", {"": []}), TODO: this returns all roles, is this expected?
        # Non existent role
        (
            "non_existent_role",
            {"non_existent_role": {"permissions": []}},
        ),
    )
    @unpack
    def test_get_permissions_for_roles(self, role_name, expected_permissions):
        """Test retrieving permissions for roles in the current environment.

        Expected result:
            - Permissions are correctly retrieved for the given roles and scope.
            - The permissions match the expected permissions.
        """
        assigned_permissions = get_permissions_for_roles(RoleData(name=role_name))

        self.assertEqual(assigned_permissions, expected_permissions)

    @ddt_data(
        # Role assigned to multiple users in different scopes
        (
            "library_user",
            "english_101",
            [
                PermissionData(action=ActionData(name="view_library"), effect="allow"),
                PermissionData(
                    action=ActionData(name="view_library_team"), effect="allow"
                ),
                PermissionData(
                    action=ActionData(name="reuse_library_content"),
                    effect="allow",
                ),
            ],
        ),
        # Role assigned to single user in single scope
        (
            "library_author",
            "history_201",
            [
                PermissionData(
                    action=ActionData(name="delete_library_content"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(name="publish_library_content"),
                    effect="allow",
                ),
                PermissionData(action=ActionData(name="edit_library"), effect="allow"),
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
        # Role assigned to single user in multiple scopes
        (
            "library_admin",
            "math_101",
            [
                PermissionData(
                    action=ActionData(name="delete_library"), effect="allow"
                ),
                PermissionData(
                    action=ActionData(name="publish_library"), effect="allow"
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
    )
    @unpack
    def test_get_permissions_for_active_role_in_specific_scope(
        self, role_name, scope_name, expected_permissions
    ):
        """Test retrieving permissions for a specific role after role assignments.

        Expected result:
            - Permissions are correctly retrieved for the given role.
            - The permissions match the expected permissions for the role.
        """
        assigned_permissions = get_permissions_for_active_roles_in_scope(
            ScopeData(name=scope_name), RoleData(name=role_name)
        )

        self.assertIn(role_name, assigned_permissions)
        self.assertEqual(
            assigned_permissions[role_name]["permissions"],
            expected_permissions,
        )

    @ddt_data(
        (
            "*",
            {
                "library_admin",
                "library_author",
                "library_collaborator",
                "library_user",
            },
        ),
    )
    @unpack
    def test_get_roles_in_scope(self, scope_name, expected_roles):
        """Test retrieving roles definitions in a specific scope_name.

        Currently, this function returns all roles defined in the system because
        we're using only lib:* scope_name. This should be updated when we have more
        (template) scopes in the policy file.

        Expected result:
            - Roles in the given scope_name are correctly retrieved.
        """
        # Need to cheat here and use library data class to get lib@* scope_name
        # TODO: it'd be better to have our own policies for testing but for now we're using
        # the existing ones in authz.policy
        roles_in_scope = get_role_definitions_in_scope(
            ContentLibraryData(library_id=scope_name)
        )

        role_names = {role.name for role in roles_in_scope}
        self.assertEqual(role_names, expected_roles)

    @ddt_data(
        ("alice", "math_101", {"library_admin"}),
        ("bob", "history_201", {"library_author"}),
        ("carol", "science_301", {"library_collaborator"}),
        ("dave", "english_101", {"library_user"}),
        ("eve", "physics_401", {"library_admin"}),
        ("eve", "chemistry_501", {"library_author"}),
        ("eve", "biology_601", {"library_user"}),
        ("grace", "math_advanced", {"library_collaborator"}),
        ("ivy", "cs_101", {"library_admin"}),
        ("jack", "cs_101", {"library_author"}),
        ("kate", "cs_101", {"library_user"}),
        ("liam", "art_101", {"library_author"}),
        ("liam", "art_201", {"library_author"}),
        ("liam", "art_301", {"library_author"}),
        ("maya", "economics_101", {"library_admin"}),
        ("noah", "economics_101", {"library_collaborator"}),
        ("olivia", "economics_101", {"library_user"}),
        ("peter", "project_alpha", {"library_admin"}),
        ("peter", "project_beta", {"library_author"}),
        ("peter", "project_gamma", {"library_collaborator"}),
        ("peter", "project_delta", {"library_user"}),
        ("non_existent_user", "math_101", set()),
        ("alice", "non_existent_scope", set()),
        ("non_existent_user", "non_existent_scope", set()),
    )
    @unpack
    def test_get_subject_role_assignments_in_scope(
        self, subject_name, scope_name, expected_roles
    ):
        """Test retrieving roles assigned to a subject in a specific scope_id.

        Expected result:
            - Roles assigned to the user in the given scope_id are correctly retrieved.
        """
        role_assignments = get_subject_role_assignments_in_scope(
            SubjectData(name=subject_name), ScopeData(name=scope_name)
        )

        role_names = {assignment.role.name for assignment in role_assignments}
        self.assertEqual(role_names, expected_roles)

    @ddt_data(
        (
            "alice",
            [
                RoleData(
                    name="library_admin",
                    permissions=[
                        PermissionData(
                            action=ActionData(name="delete_library"),
                            effect="allow",
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
                            action=ActionData(name="create_library"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(name="create_library_collection"),
                            effect="allow",
                        ),
                    ],
                ),
            ],
        ),
        (
            "eve",
            [
                RoleData(
                    name="library_admin",
                    permissions=[
                        PermissionData(
                            action=ActionData(name="delete_library"),
                            effect="allow",
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
                            action=ActionData(name="create_library"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(name="create_library_collection"),
                            effect="allow",
                        ),
                    ],
                ),
                RoleData(
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
                            action=ActionData(name="edit_library"),
                            effect="allow",
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
                RoleData(
                    name="library_user",
                    permissions=[
                        PermissionData(
                            action=ActionData(name="view_library"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(name="view_library_team"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(name="reuse_library_content"),
                            effect="allow",
                        ),
                    ],
                ),
            ],
        ),
        (
            "frank",
            [
                RoleData(
                    name="library_user",
                    permissions=[
                        PermissionData(
                            action=ActionData(name="view_library"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(name="view_library_team"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(name="reuse_library_content"),
                            effect="allow",
                        ),
                    ],
                ),
            ],
        ),
        ("non_existent_user", []),
    )
    @unpack
    def test_get_all_role_assignments_scopes(self, subject_name, expected_roles):
        """Test retrieving all roles assigned to a subject across all scopes.

        Expected result:
            - All roles assigned to the subject across all scopes are correctly retrieved.
            - Each role includes its associated permissions.
        """
        role_assignments = get_subject_role_assignments(SubjectData(name=subject_name))

        self.assertEqual(len(role_assignments), len(expected_roles))
        for expected_role in expected_roles:
            # Compare the role part of the assignment
            found = any(
                assignment.role == expected_role for assignment in role_assignments
            )
            self.assertTrue(
                found, f"Expected role {expected_role} not found in assignments"
            )

    @ddt_data(
        ("library_admin", "math_101", 1),
        ("library_author", "history_201", 1),
        ("library_collaborator", "science_301", 1),
        ("library_user", "english_101", 1),
        ("library_admin", "physics_401", 1),
        ("library_author", "chemistry_501", 1),
        ("library_user", "biology_601", 1),
        ("library_collaborator", "math_advanced", 2),
        ("library_admin", "cs_101", 1),
        ("library_author", "cs_101", 1),
        ("library_user", "cs_101", 1),
        ("library_author", "art_101", 1),
        ("library_author", "art_201", 1),
        ("library_author", "art_301", 1),
        ("library_admin", "economics_101", 1),
        ("library_collaborator", "economics_101", 1),
        ("library_user", "economics_101", 1),
        ("library_admin", "project_alpha", 1),
        ("library_author", "project_beta", 1),
        ("library_collaborator", "project_gamma", 1),
        ("library_user", "project_delta", 1),
        ("non_existent_role", "any_library", 0),
        ("library_admin", "non_existent_scope", 0),
        ("non_existent_role", "non_existent_scope", 0),
    )
    @unpack
    def test_get_role_assignments_in_scope(self, role_name, scope_name, expected_count):
        """Test retrieving role assignments in a specific scope.

        Expected result:
            - The number of role assignments in the given scope is correctly retrieved.
        """
        role_assignments = get_subjects_role_assignments_for_role_in_scope(
            RoleData(name=role_name), ScopeData(name=scope_name)
        )

        self.assertEqual(len(role_assignments), expected_count)


@ddt
class TestRoleAssignmentAPI(RolesTestSetupMixin):
    """Test cases for role assignment API functions.

    The enforcer used in these tests cases is the default global enforcer
    instance from `openedx_authz.engine.enforcer` automatically used by
    the API to ensure consistency across tests and production environments.

    In case a different enforcer configuration is needed, consider mocking the
    enforcer instance in the `openedx_authz.api.roles` module.
    """

    @ddt_data(
        (["mary", "john"], "library_user", "batch_test", True),
        (
            ["paul", "diana", "lila"],
            "library_collaborator",
            "math_advanced",
            True,
        ),
        (["sarina", "ty"], "library_author", "art_101", True),
        (["fran", "bob"], "library_admin", "cs_101", True),
        (
            ["anna", "tom", "jerry"],
            "library_user",
            "history_201",
            True,
        ),
        ("joe", "library_collaborator", "science_301", False),
        ("nina", "library_author", "english_101", False),
        ("oliver", "library_admin", "math_101", False),
    )
    @unpack
    def test_batch_assign_role_to_subjects_in_scope(
        self, subject_names, role, scope_name, batch
    ):
        """Test assigning a role to a single or multiple subjects in a specific scope.

        Expected result:
            - Role is successfully assigned to all specified subjects in the given scope.
            - Each subject has the correct permissions associated with the assigned role.
            - Each subject can perform actions allowed by the role.
        """
        if batch:
            subjects_list = []
            for subject in subject_names:
                subjects_list.append(SubjectData(name=subject))
            batch_assign_role_to_subjects_in_scope(
                subjects_list,
                RoleData(name=role),
                ScopeData(name=scope_name),
            )
            user_roles = get_subject_role_assignments_in_scope(
                SubjectData(name=subject), ScopeData(name=scope_name)
            )
            role_names = {assignment.role.name for assignment in user_roles}
            self.assertIn(role, role_names)
        else:
            assign_role_to_subject_in_scope(
                SubjectData(name=subject_names),
                RoleData(name=role),
                ScopeData(name=scope_name),
            )
            user_roles = get_subject_role_assignments_in_scope(
                SubjectData(name=subject_names), ScopeData(name=scope_name)
            )
            role_names = {assignment.role.name for assignment in user_roles}
            self.assertIn(role, role_names)

    @ddt_data(
        (["mary", "john"], "library_user", "batch_test", True),
        (
            ["paul", "diana", "lila"],
            "library_collaborator",
            "math_advanced",
            True,
        ),
        (["sarina", "ty"], "library_author", "art_101", True),
        (["fran", "bob"], "library_admin", "cs_101", True),
        (
            ["anna", "tom", "jerry"],
            "library_user",
            "history_201",
            True,
        ),
        ("joe", "library_collaborator", "science_301", False),
        ("nina", "library_author", "english_101", False),
        ("oliver", "library_admin", "math_101", False),
    )
    @unpack
    def test_unassign_role_from_subject_in_scope(
        self, subject_names, role, scope_name, batch
    ):
        """Test unassigning a role from a subject or multiple subjects in a specific scope_name.

        Expected result:
            - Role is successfully unassigned from the subject in the specified scope_name.
            - Subject no longer has permissions associated with the unassigned role.
            - The subject cannot perform actions that were allowed by the role.
        """
        if batch:
            for subject in subject_names:
                unassign_role_from_subject_in_scope(
                    SubjectData(name=subject),
                    RoleData(name=role),
                    ScopeData(name=scope_name),
                )
                user_roles = get_subject_role_assignments_in_scope(
                    SubjectData(name=subject), ScopeData(name=scope_name)
                )
                role_names = {assignment.role.name for assignment in user_roles}
                self.assertNotIn(role, role_names)
        else:
            unassign_role_from_subject_in_scope(
                SubjectData(name=subject_names),
                RoleData(name=role),
                ScopeData(name=scope_name),
            )
            user_roles = get_subject_role_assignments_in_scope(
                SubjectData(name=subject_names), ScopeData(name=scope_name)
            )
            role_names = {assignment.role.name for assignment in user_roles}
            self.assertNotIn(role, role_names)

    @ddt_data(
        (
            "math_101",
            [
                RoleAssignmentData(
                    subject=SubjectData(name="alice"),
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
                )
            ],
        ),
        (
            "history_201",
            [
                RoleAssignmentData(
                    subject=SubjectData(name="bob"),
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
                )
            ],
        ),
        (
            "science_301",
            [
                RoleAssignmentData(
                    subject=SubjectData(name="carol"),
                    role=RoleData(
                        name="library_collaborator",
                        permissions=[
                            PermissionData(
                                action=ActionData(name="edit_library"), effect="allow"
                            ),
                            PermissionData(
                                action=ActionData(name="delete_library_content"),
                                effect="allow",
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
                    scope=ScopeData(name="science_301"),
                )
            ],
        ),
        (
            "english_101",
            [
                RoleAssignmentData(
                    subject=SubjectData(name="dave"),
                    role=RoleData(
                        name="library_user",
                        permissions=[
                            PermissionData(
                                action=ActionData(name="view_library"), effect="allow"
                            ),
                            PermissionData(
                                action=ActionData(name="view_library_team"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(name="reuse_library_content"),
                                effect="allow",
                            ),
                        ],
                    ),
                    scope=ScopeData(name="english_101"),
                )
            ],
        ),
        ("non_existent_scope", []),
    )
    @unpack
    def test_get_all_role_assignments_in_scope(self, scope_name, expected_assignments):
        """Test retrieving all role assignments in a specific scope.

        Expected result:
            - All role assignments in the specified scope are correctly retrieved.
            - Each assignment includes the subject, role, and scope information with permissions.
        """
        role_assignments = get_all_subject_role_assignments_in_scope(
            ScopeData(name=scope_name)
        )

        self.assertEqual(len(role_assignments), len(expected_assignments))
        for assignment in role_assignments:
            self.assertIn(assignment, expected_assignments)
