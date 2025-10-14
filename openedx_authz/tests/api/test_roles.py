"""Test cases for roles API functions.

In this test suite, we will verify the functionality of the roles API,
including role creation, assignment, permission management, and querying
roles and permissions within specific scopes.
"""

import casbin
from ddt import data as ddt_data
from ddt import ddt, unpack
from django.test import TestCase

from openedx_authz.api.data import (
    ActionData,
    ContentLibraryData,
    PermissionData,
    RoleAssignmentData,
    RoleData,
    ScopeData,
    SubjectData,
)
from openedx_authz.api.roles import (
    assign_role_to_subject_in_scope,
    batch_assign_role_to_subjects_in_scope,
    get_all_subject_role_assignments_in_scope,
    get_permissions_for_active_roles_in_scope,
    get_permissions_for_single_role,
    get_role_definitions_in_scope,
    get_subject_role_assignments,
    get_subject_role_assignments_for_role_in_scope,
    get_subject_role_assignments_in_scope,
    unassign_role_from_subject_in_scope,
)
from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.engine.utils import migrate_policy_between_enforcers


class BaseRolesTestCase(TestCase):
    """Base test case with helper methods for roles testing.

    This class provides the infrastructure for testing roles without
    loading any specific test data. Subclasses should override setUpClass
    to define their own test data assignments.
    """

    @classmethod
    def _seed_database_with_policies(cls):
        """Seed the database with policies from the policy file.

        This simulates the one-time database seeding that would happen
        during application deployment, separate from the runtime policy loading.
        """
        global_enforcer = AuthzEnforcer.get_enforcer()
        global_enforcer.load_policy()
        migrate_policy_between_enforcers(
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
                - subject_name (str): External key of the subject (e.g., 'john_doe').
                - role_name (str): External key of the role to assign (e.g., 'library_admin').
                - scope_name (str): External key of the scope in which to assign the role (e.g., 'lib:Org1:math_101').
        """
        if assignments:
            for assignment in assignments:
                assign_role_to_subject_in_scope(
                    subject=SubjectData(
                        external_key=assignment["subject_name"],
                    ),
                    role=RoleData(external_key=assignment["role_name"]),
                    scope=ScopeData(external_key=assignment["scope_name"]),
                )

    @classmethod
    def setUpClass(cls):
        """Set up test class environment.

        Seeds the database with policies. Subclasses should override this
        to add their specific role assignments by calling _assign_roles_to_users.
        """
        super().setUpClass()
        cls._seed_database_with_policies()


class RolesTestSetupMixin(BaseRolesTestCase):
    """Test case with comprehensive role assignments for general roles testing."""

    @classmethod
    def setUpClass(cls):
        """Set up test class environment with predefined role assignments."""
        super().setUpClass()
        # Define specific assignments for this test class
        assignments = [
            # Basic library roles from authz.policy
            {
                "subject_name": "alice",
                "role_name": "library_admin",
                "scope_name": "lib:Org1:math_101",
            },
            {
                "subject_name": "bob",
                "role_name": "library_author",
                "scope_name": "lib:Org1:history_201",
            },
            {
                "subject_name": "carol",
                "role_name": "library_collaborator",
                "scope_name": "lib:Org1:science_301",
            },
            {
                "subject_name": "dave",
                "role_name": "library_user",
                "scope_name": "lib:Org1:english_101",
            },
            # Multi-role assignments - same subject with different roles in different libraries
            {
                "subject_name": "eve",
                "role_name": "library_admin",
                "scope_name": "lib:Org2:physics_401",
            },
            {
                "subject_name": "eve",
                "role_name": "library_author",
                "scope_name": "lib:Org2:chemistry_501",
            },
            {
                "subject_name": "eve",
                "role_name": "library_user",
                "scope_name": "lib:Org2:biology_601",
            },
            # Multiple subjects with same role in same scope
            {
                "subject_name": "grace",
                "role_name": "library_collaborator",
                "scope_name": "lib:Org1:math_advanced",
            },
            {
                "subject_name": "heidi",
                "role_name": "library_collaborator",
                "scope_name": "lib:Org1:math_advanced",
            },
            # Hierarchical scope assignments - different specificity levels
            {
                "subject_name": "ivy",
                "role_name": "library_admin",
                "scope_name": "lib:Org3:cs_101",
            },
            {
                "subject_name": "jack",
                "role_name": "library_author",
                "scope_name": "lib:Org3:cs_101",
            },
            {
                "subject_name": "kate",
                "role_name": "library_user",
                "scope_name": "lib:Org3:cs_101",
            },
            # Edge case: same user, same role, different scopes
            {
                "subject_name": "liam",
                "role_name": "library_author",
                "scope_name": "lib:Org4:art_101",
            },
            {
                "subject_name": "liam",
                "role_name": "library_author",
                "scope_name": "lib:Org4:art_201",
            },
            {
                "subject_name": "liam",
                "role_name": "library_author",
                "scope_name": "lib:Org4:art_301",
            },
            # Mixed permission levels across libraries for comprehensive testing
            {
                "subject_name": "maya",
                "role_name": "library_admin",
                "scope_name": "lib:Org5:economics_101",
            },
            {
                "subject_name": "noah",
                "role_name": "library_collaborator",
                "scope_name": "lib:Org5:economics_101",
            },
            {
                "subject_name": "olivia",
                "role_name": "library_user",
                "scope_name": "lib:Org5:economics_101",
            },
            # Complex multi-library, multi-role scenario
            {
                "subject_name": "peter",
                "role_name": "library_admin",
                "scope_name": "lib:Org6:project_alpha",
            },
            {
                "subject_name": "peter",
                "role_name": "library_author",
                "scope_name": "lib:Org6:project_beta",
            },
            {
                "subject_name": "peter",
                "role_name": "library_collaborator",
                "scope_name": "lib:Org6:project_gamma",
            },
            {
                "subject_name": "peter",
                "role_name": "library_user",
                "scope_name": "lib:Org6:project_delta",
            },
            {
                "subject_name": "frank",
                "role_name": "library_user",
                "scope_name": "lib:Org6:project_epsilon",
            },
        ]
        cls._assign_roles_to_users(assignments=assignments)

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        AuthzEnforcer.get_enforcer().load_policy()  # Load policies before each test to simulate fresh start

    def tearDown(self):
        """Clean up after each test to ensure isolation."""
        super().tearDown()
        AuthzEnforcer.get_enforcer().clear_policy()  # Clear policies after each test to ensure isolation


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
            [
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
                    action=ActionData(external_key="delete_library_content"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="publish_library_content"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="delete_library_collection"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="create_library"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="create_library_collection"),
                    effect="allow",
                ),
            ],
        ),
        # Library Author role with actual permissions from authz.policy
        (
            "library_author",
            [
                PermissionData(
                    action=ActionData(external_key="delete_library_content"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="publish_library_content"),
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
                    action=ActionData(external_key="create_library_collection"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="edit_library_collection"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="delete_library_collection"),
                    effect="allow",
                ),
            ],
        ),
        # Library Collaborator role with actual permissions from authz.policy
        (
            "library_collaborator",
            [
                PermissionData(
                    action=ActionData(external_key="edit_library"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="delete_library_content"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="manage_library_tags"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="create_library_collection"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="edit_library_collection"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="delete_library_collection"),
                    effect="allow",
                ),
            ],
        ),
        # Library User role with minimal permissions
        (
            "library_user",
            [
                PermissionData(
                    action=ActionData(external_key="view_library"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="view_library_team"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="reuse_library_content"),
                    effect="allow",
                ),
            ],
        ),
        # Non existent role
        (
            "non_existent_role",
            [],
        ),
    )
    @unpack
    def test_get_permissions_for_roles(self, role_name, expected_permissions):
        """Test retrieving permissions for roles in the current environment.

        Expected result:
            - Permissions are correctly retrieved for the given roles and scope.
            - The permissions match the expected permissions.
        """
        assigned_permissions = get_permissions_for_single_role(
            RoleData(external_key=role_name)
        )

        self.assertEqual(assigned_permissions, expected_permissions)

    @ddt_data(
        # Role assigned to multiple users in different scopes
        (
            "library_user",
            "lib:Org1:english_101",
            [
                PermissionData(
                    action=ActionData(external_key="view_library"), effect="allow"
                ),
                PermissionData(
                    action=ActionData(external_key="view_library_team"), effect="allow"
                ),
                PermissionData(
                    action=ActionData(external_key="reuse_library_content"),
                    effect="allow",
                ),
            ],
        ),
        # Role assigned to single user in single scope
        (
            "library_author",
            "lib:Org1:history_201",
            [
                PermissionData(
                    action=ActionData(external_key="delete_library_content"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="publish_library_content"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="edit_library"), effect="allow"
                ),
                PermissionData(
                    action=ActionData(external_key="manage_library_tags"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="create_library_collection"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="edit_library_collection"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="delete_library_collection"),
                    effect="allow",
                ),
            ],
        ),
        # Role assigned to single user in multiple scopes
        (
            "library_admin",
            "lib:Org1:math_101",
            [
                PermissionData(
                    action=ActionData(external_key="delete_library"), effect="allow"
                ),
                PermissionData(
                    action=ActionData(external_key="publish_library"), effect="allow"
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
                    action=ActionData(external_key="delete_library_content"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="publish_library_content"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="delete_library_collection"),
                    effect="allow",
                ),
                PermissionData(
                    action=ActionData(external_key="create_library"), effect="allow"
                ),
                PermissionData(
                    action=ActionData(external_key="create_library_collection"),
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
            ScopeData(external_key=scope_name), RoleData(external_key=role_name)
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
        """Test retrieving roles definitions in a specific scope.

        Currently, this function returns all roles defined in the system because
        we're using only lib:* scope (which maps to lib^* internally). This should
        be updated when we have more (template) scopes in the policy file.

        Expected result:
            - Roles in the given scope are correctly retrieved.
        """
        # TODO: cheat and use ContentLibraryData until we have more scope types
        roles_in_scope = get_role_definitions_in_scope(
            ContentLibraryData(external_key=scope_name),
        )

        role_names = {role.external_key for role in roles_in_scope}
        self.assertEqual(role_names, expected_roles)

    @ddt_data(
        ("alice", "lib:Org1:math_101", {"library_admin"}),
        ("bob", "lib:Org1:history_201", {"library_author"}),
        ("carol", "lib:Org1:science_301", {"library_collaborator"}),
        ("dave", "lib:Org1:english_101", {"library_user"}),
        ("eve", "lib:Org2:physics_401", {"library_admin"}),
        ("eve", "lib:Org2:chemistry_501", {"library_author"}),
        ("eve", "lib:Org2:biology_601", {"library_user"}),
        ("grace", "lib:Org1:math_advanced", {"library_collaborator"}),
        ("ivy", "lib:Org3:cs_101", {"library_admin"}),
        ("jack", "lib:Org3:cs_101", {"library_author"}),
        ("kate", "lib:Org3:cs_101", {"library_user"}),
        ("liam", "lib:Org4:art_101", {"library_author"}),
        ("liam", "lib:Org4:art_201", {"library_author"}),
        ("liam", "lib:Org4:art_301", {"library_author"}),
        ("maya", "lib:Org5:economics_101", {"library_admin"}),
        ("noah", "lib:Org5:economics_101", {"library_collaborator"}),
        ("olivia", "lib:Org5:economics_101", {"library_user"}),
        ("peter", "lib:Org6:project_alpha", {"library_admin"}),
        ("peter", "lib:Org6:project_beta", {"library_author"}),
        ("peter", "lib:Org6:project_gamma", {"library_collaborator"}),
        ("peter", "lib:Org6:project_delta", {"library_user"}),
        ("non_existent_user", "lib:Org1:math_101", set()),
        ("alice", "lib:Org999:non_existent_scope", set()),
        ("non_existent_user", "lib:Org999:non_existent_scope", set()),
    )
    @unpack
    def test_get_subject_role_assignments_in_scope(
        self, subject_name, scope_name, expected_roles
    ):
        """Test retrieving roles assigned to a subject in a specific scope.

        Expected result:
            - Roles assigned to the subject in the given scope are correctly retrieved.
        """
        role_assignments = get_subject_role_assignments_in_scope(
            SubjectData(external_key=subject_name), ScopeData(external_key=scope_name)
        )

        role_names = {r.external_key for assignment in role_assignments for r in assignment.roles}
        self.assertEqual(role_names, expected_roles)

    @ddt_data(
        (
            "alice",
            [
                RoleData(
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
                            action=ActionData(external_key="delete_library_content"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(external_key="publish_library_content"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(external_key="delete_library_collection"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(external_key="create_library"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(external_key="create_library_collection"),
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
                            action=ActionData(external_key="delete_library_content"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(external_key="publish_library_content"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(external_key="delete_library_collection"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(external_key="create_library"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(external_key="create_library_collection"),
                            effect="allow",
                        ),
                    ],
                ),
                RoleData(
                    external_key="library_author",
                    permissions=[
                        PermissionData(
                            action=ActionData(external_key="delete_library_content"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(external_key="publish_library_content"),
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
                            action=ActionData(external_key="create_library_collection"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(external_key="edit_library_collection"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(external_key="delete_library_collection"),
                            effect="allow",
                        ),
                    ],
                ),
                RoleData(
                    external_key="library_user",
                    permissions=[
                        PermissionData(
                            action=ActionData(external_key="view_library"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(external_key="view_library_team"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(external_key="reuse_library_content"),
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
                    external_key="library_user",
                    permissions=[
                        PermissionData(
                            action=ActionData(external_key="view_library"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(external_key="view_library_team"),
                            effect="allow",
                        ),
                        PermissionData(
                            action=ActionData(external_key="reuse_library_content"),
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
        role_assignments = get_subject_role_assignments(
            SubjectData(external_key=subject_name)
        )

        self.assertEqual(len(role_assignments), len(expected_roles))
        for expected_role in expected_roles:
            # Compare the role part of the assignment
            found = any(
                expected_role in assignment.roles for assignment in role_assignments
            )
            self.assertTrue(
                found, f"Expected role {expected_role} not found in assignments"
            )

    @ddt_data(
        ("library_admin", "lib:Org1:math_101", 1),
        ("library_author", "lib:Org1:history_201", 1),
        ("library_collaborator", "lib:Org1:science_301", 1),
        ("library_user", "lib:Org1:english_101", 1),
        ("library_admin", "lib:Org2:physics_401", 1),
        ("library_author", "lib:Org2:chemistry_501", 1),
        ("library_user", "lib:Org2:biology_601", 1),
        ("library_collaborator", "lib:Org1:math_advanced", 2),
        ("library_admin", "lib:Org3:cs_101", 1),
        ("library_author", "lib:Org3:cs_101", 1),
        ("library_user", "lib:Org3:cs_101", 1),
        ("library_author", "lib:Org4:art_101", 1),
        ("library_author", "lib:Org4:art_201", 1),
        ("library_author", "lib:Org4:art_301", 1),
        ("library_admin", "lib:Org5:economics_101", 1),
        ("library_collaborator", "lib:Org5:economics_101", 1),
        ("library_user", "lib:Org5:economics_101", 1),
        ("library_admin", "lib:Org6:project_alpha", 1),
        ("library_author", "lib:Org6:project_beta", 1),
        ("library_collaborator", "lib:Org6:project_gamma", 1),
        ("library_user", "lib:Org6:project_delta", 1),
        ("non_existent_role", "sc:any_library", 0),
        ("library_admin", "sc:non_existent_scope", 0),
        ("non_existent_role", "sc:non_existent_scope", 0),
    )
    @unpack
    def test_get_role_assignments_in_scope(self, role_name, scope_name, expected_count):
        """Test retrieving role assignments in a specific scope.

        Expected result:
            - The number of role assignments in the given scope is correctly retrieved.
        """
        role_assignments = get_subject_role_assignments_for_role_in_scope(
            RoleData(external_key=role_name), ScopeData(external_key=scope_name)
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
        (["mary", "john"], "library_user", "sc:batch_test", True),
        (
            ["paul", "diana", "lila"],
            "library_collaborator",
            "lib:Org1:math_advanced",
            True,
        ),
        (["sarina", "ty"], "library_author", "lib:Org4:art_101", True),
        (["fran", "bob"], "library_admin", "lib:Org3:cs_101", True),
        (
            ["anna", "tom", "jerry"],
            "library_user",
            "lib:Org1:history_201",
            True,
        ),
        ("joe", "library_collaborator", "lib:Org1:science_301", False),
        ("nina", "library_author", "lib:Org1:english_101", False),
        ("oliver", "library_admin", "lib:Org1:math_101", False),
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
                subjects_list.append(SubjectData(external_key=subject))
            batch_assign_role_to_subjects_in_scope(
                subjects_list,
                RoleData(external_key=role),
                ScopeData(external_key=scope_name),
            )
            for subject_name in subject_names:
                user_roles = get_subject_role_assignments_in_scope(
                    SubjectData(external_key=subject_name), ScopeData(external_key=scope_name)
                )
                role_names = {r.external_key for assignment in user_roles for r in assignment.roles}
                self.assertIn(role, role_names)
        else:
            assign_role_to_subject_in_scope(
                SubjectData(external_key=subject_names),
                RoleData(external_key=role),
                ScopeData(external_key=scope_name),
            )
            user_roles = get_subject_role_assignments_in_scope(
                SubjectData(external_key=subject_names),
                ScopeData(external_key=scope_name),
            )
            role_names = {r.external_key for assignment in user_roles for r in assignment.roles}
            self.assertIn(role, role_names)

    @ddt_data(
        (["mary", "john"], "library_user", "sc:batch_test", True),
        (
            ["paul", "diana", "lila"],
            "library_collaborator",
            "lib:Org1:math_advanced",
            True,
        ),
        (["sarina", "ty"], "library_author", "lib:Org4:art_101", True),
        (["fran", "bob"], "library_admin", "lib:Org3:cs_101", True),
        (
            ["anna", "tom", "jerry"],
            "library_user",
            "lib:Org1:history_201",
            True,
        ),
        ("joe", "library_collaborator", "lib:Org1:science_301", False),
        ("nina", "library_author", "lib:Org1:english_101", False),
        ("oliver", "library_admin", "lib:Org1:math_101", False),
    )
    @unpack
    def test_unassign_role_from_subject_in_scope(
        self, subject_names, role, scope_name, batch
    ):
        """Test unassigning a role from a subject or multiple subjects in a specific scope.

        Expected result:
            - Role is successfully unassigned from the subject in the specified scope.
            - Subject no longer has permissions associated with the unassigned role.
            - The subject cannot perform actions that were allowed by the role.
        """
        if batch:
            for subject in subject_names:
                unassign_role_from_subject_in_scope(
                    SubjectData(external_key=subject),
                    RoleData(external_key=role),
                    ScopeData(external_key=scope_name),
                )
                user_roles = get_subject_role_assignments_in_scope(
                    SubjectData(external_key=subject),
                    ScopeData(external_key=scope_name),
                )
                role_names = {r.external_key for assignment in user_roles for r in assignment.roles}
                self.assertNotIn(role, role_names)
        else:
            unassign_role_from_subject_in_scope(
                SubjectData(external_key=subject_names),
                RoleData(external_key=role),
                ScopeData(external_key=scope_name),
            )
            user_roles = get_subject_role_assignments_in_scope(
                SubjectData(external_key=subject_names),
                ScopeData(external_key=scope_name),
            )
            role_names = {r.external_key for assignment in user_roles for r in assignment.roles}
            self.assertNotIn(role, role_names)

    @ddt_data(
        (
            "lib:Org1:math_101",
            [
                RoleAssignmentData(
                    subject=SubjectData(external_key="alice"),
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
                    scope=ScopeData(external_key="lib:Org1:math_101"),
                )
            ],
        ),
        (
            "lib:Org1:history_201",
            [
                RoleAssignmentData(
                    subject=SubjectData(external_key="bob"),
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
                    scope=ScopeData(external_key="lib:Org1:history_201"),
                )
            ],
        ),
        (
            "lib:Org1:science_301",
            [
                RoleAssignmentData(
                    subject=SubjectData(external_key="carol"),
                    roles=[RoleData(
                        external_key="library_collaborator",
                        permissions=[
                            PermissionData(
                                action=ActionData(external_key="edit_library"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(
                                    external_key="delete_library_content"
                                ),
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
                    scope=ScopeData(external_key="lib:Org1:science_301"),
                )
            ],
        ),
        (
            "lib:Org1:english_101",
            [
                RoleAssignmentData(
                    subject=SubjectData(external_key="dave"),
                    roles=[RoleData(
                        external_key="library_user",
                        permissions=[
                            PermissionData(
                                action=ActionData(external_key="view_library"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(external_key="view_library_team"),
                                effect="allow",
                            ),
                            PermissionData(
                                action=ActionData(external_key="reuse_library_content"),
                                effect="allow",
                            ),
                        ],
                    )],
                    scope=ScopeData(external_key="lib:Org1:english_101"),
                )
            ],
        ),
        ("sc:non_existent_scope", []),
    )
    @unpack
    def test_get_all_role_assignments_in_scope(self, scope_name, expected_assignments):
        """Test retrieving all role assignments in a specific scope.

        Expected result:
            - All role assignments in the specified scope are correctly retrieved.
            - Each assignment includes the subject, role, and scope information with permissions.
        """
        role_assignments = get_all_subject_role_assignments_in_scope(
            ScopeData(external_key=scope_name)
        )

        self.assertEqual(len(role_assignments), len(expected_assignments))
        for assignment in role_assignments:
            self.assertIn(assignment, expected_assignments)
