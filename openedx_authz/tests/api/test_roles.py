"""Test cases for roles API functions.

In this test suite, we will verify the functionality of the roles API,
including role creation, assignment, permission management, and querying
roles and permissions within specific scopes.
"""

import casbin
import pkg_resources
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
    get_scopes_for_subject_and_permission,
    get_subject_role_assignments,
    get_subject_role_assignments_for_role_in_scope,
    get_subject_role_assignments_in_scope,
    get_subjects_for_role_in_scope,
    unassign_role_from_subject_in_scope,
)
from openedx_authz.constants import roles
from openedx_authz.constants.roles import (
    LIBRARY_ADMIN_PERMISSIONS,
    LIBRARY_AUTHOR_PERMISSIONS,
    LIBRARY_CONTRIBUTOR_PERMISSIONS,
    LIBRARY_USER_PERMISSIONS,
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
        model_path = pkg_resources.resource_filename("openedx_authz.engine", "config/model.conf")
        policy_path = pkg_resources.resource_filename("openedx_authz.engine", "config/authz.policy")

        migrate_policy_between_enforcers(
            source_enforcer=casbin.Enforcer(model_path, policy_path),
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
        AuthzEnforcer.get_enforcer().stop_auto_load_policy()
        # Enable auto-save to ensure policies are saved to the database
        # This is necessary because the tests are not using auto-load policy
        AuthzEnforcer.get_enforcer().enable_auto_save(True)
        cls._seed_database_with_policies()

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        AuthzEnforcer.get_enforcer().load_policy()  # Load policies before each test to simulate fresh start

    def tearDown(self):
        """Clean up after each test to ensure isolation."""
        super().tearDown()
        AuthzEnforcer.get_enforcer().clear_policy()  # Clear policies after each test to ensure isolation


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
                "role_name": roles.LIBRARY_ADMIN.external_key,
                "scope_name": "lib:Org1:math_101",
            },
            {
                "subject_name": "bob",
                "role_name": roles.LIBRARY_AUTHOR.external_key,
                "scope_name": "lib:Org1:history_201",
            },
            {
                "subject_name": "carol",
                "role_name": roles.LIBRARY_CONTRIBUTOR.external_key,
                "scope_name": "lib:Org1:science_301",
            },
            {
                "subject_name": "dave",
                "role_name": roles.LIBRARY_USER.external_key,
                "scope_name": "lib:Org1:english_101",
            },
            # Multi-role assignments - same subject with different roles in different libraries
            {
                "subject_name": "eve",
                "role_name": roles.LIBRARY_ADMIN.external_key,
                "scope_name": "lib:Org2:physics_401",
            },
            {
                "subject_name": "eve",
                "role_name": roles.LIBRARY_AUTHOR.external_key,
                "scope_name": "lib:Org2:chemistry_501",
            },
            {
                "subject_name": "eve",
                "role_name": roles.LIBRARY_USER.external_key,
                "scope_name": "lib:Org2:biology_601",
            },
            # Multiple subjects with same role in same scope
            {
                "subject_name": "grace",
                "role_name": roles.LIBRARY_CONTRIBUTOR.external_key,
                "scope_name": "lib:Org1:math_advanced",
            },
            {
                "subject_name": "heidi",
                "role_name": roles.LIBRARY_CONTRIBUTOR.external_key,
                "scope_name": "lib:Org1:math_advanced",
            },
            # Hierarchical scope assignments - different specificity levels
            {
                "subject_name": "ivy",
                "role_name": roles.LIBRARY_ADMIN.external_key,
                "scope_name": "lib:Org3:cs_101",
            },
            {
                "subject_name": "jack",
                "role_name": roles.LIBRARY_AUTHOR.external_key,
                "scope_name": "lib:Org3:cs_101",
            },
            {
                "subject_name": "kate",
                "role_name": roles.LIBRARY_USER.external_key,
                "scope_name": "lib:Org3:cs_101",
            },
            # Edge case: same user, same role, different scopes
            {
                "subject_name": "liam",
                "role_name": roles.LIBRARY_AUTHOR.external_key,
                "scope_name": "lib:Org4:art_101",
            },
            {
                "subject_name": "liam",
                "role_name": roles.LIBRARY_AUTHOR.external_key,
                "scope_name": "lib:Org4:art_201",
            },
            {
                "subject_name": "liam",
                "role_name": roles.LIBRARY_AUTHOR.external_key,
                "scope_name": "lib:Org4:art_301",
            },
            # Mixed permission levels across libraries for comprehensive testing
            {
                "subject_name": "maya",
                "role_name": roles.LIBRARY_ADMIN.external_key,
                "scope_name": "lib:Org5:economics_101",
            },
            {
                "subject_name": "noah",
                "role_name": roles.LIBRARY_CONTRIBUTOR.external_key,
                "scope_name": "lib:Org5:economics_101",
            },
            {
                "subject_name": "olivia",
                "role_name": roles.LIBRARY_USER.external_key,
                "scope_name": "lib:Org5:economics_101",
            },
            # Complex multi-library, multi-role scenario
            {
                "subject_name": "peter",
                "role_name": roles.LIBRARY_ADMIN.external_key,
                "scope_name": "lib:Org6:project_alpha",
            },
            {
                "subject_name": "peter",
                "role_name": roles.LIBRARY_AUTHOR.external_key,
                "scope_name": "lib:Org6:project_beta",
            },
            {
                "subject_name": "peter",
                "role_name": roles.LIBRARY_CONTRIBUTOR.external_key,
                "scope_name": "lib:Org6:project_gamma",
            },
            {
                "subject_name": "peter",
                "role_name": roles.LIBRARY_USER.external_key,
                "scope_name": "lib:Org6:project_delta",
            },
            {
                "subject_name": "frank",
                "role_name": roles.LIBRARY_USER.external_key,
                "scope_name": "lib:Org6:project_epsilon",
            },
        ]
        cls._assign_roles_to_users(assignments=assignments)


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
            roles.LIBRARY_ADMIN.external_key,
            LIBRARY_ADMIN_PERMISSIONS,
        ),
        # Library Author role with actual permissions from authz.policy
        (
            roles.LIBRARY_AUTHOR.external_key,
            LIBRARY_AUTHOR_PERMISSIONS,
        ),
        # Library Contributor role with actual permissions from authz.policy
        (
            roles.LIBRARY_CONTRIBUTOR.external_key,
            LIBRARY_CONTRIBUTOR_PERMISSIONS,
        ),
        # Library User role with minimal permissions
        (
            roles.LIBRARY_USER.external_key,
            LIBRARY_USER_PERMISSIONS,
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
        assigned_permissions = get_permissions_for_single_role(RoleData(external_key=role_name))

        self.assertEqual(assigned_permissions, expected_permissions)

    @ddt_data(
        # Role assigned to multiple users in different scopes
        (
            roles.LIBRARY_USER.external_key,
            "lib:Org1:english_101",
            LIBRARY_USER_PERMISSIONS,
        ),
        # Role assigned to single user in single scope
        (
            roles.LIBRARY_AUTHOR.external_key,
            "lib:Org1:history_201",
            LIBRARY_AUTHOR_PERMISSIONS,
        ),
        # Role assigned to single user in multiple scopes
        (
            roles.LIBRARY_ADMIN.external_key,
            "lib:Org1:math_101",
            LIBRARY_ADMIN_PERMISSIONS,
        ),
    )
    @unpack
    def test_get_permissions_for_active_role_in_specific_scope(self, role_name, scope_name, expected_permissions):
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
                roles.LIBRARY_ADMIN.external_key,
                roles.LIBRARY_AUTHOR.external_key,
                roles.LIBRARY_CONTRIBUTOR.external_key,
                roles.LIBRARY_USER.external_key,
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
        ("alice", "lib:Org1:math_101", {roles.LIBRARY_ADMIN.external_key}),
        ("bob", "lib:Org1:history_201", {roles.LIBRARY_AUTHOR.external_key}),
        ("carol", "lib:Org1:science_301", {roles.LIBRARY_CONTRIBUTOR.external_key}),
        ("dave", "lib:Org1:english_101", {roles.LIBRARY_USER.external_key}),
        ("eve", "lib:Org2:physics_401", {roles.LIBRARY_ADMIN.external_key}),
        ("eve", "lib:Org2:chemistry_501", {roles.LIBRARY_AUTHOR.external_key}),
        ("eve", "lib:Org2:biology_601", {roles.LIBRARY_USER.external_key}),
        ("grace", "lib:Org1:math_advanced", {roles.LIBRARY_CONTRIBUTOR.external_key}),
        ("ivy", "lib:Org3:cs_101", {roles.LIBRARY_ADMIN.external_key}),
        ("jack", "lib:Org3:cs_101", {roles.LIBRARY_AUTHOR.external_key}),
        ("kate", "lib:Org3:cs_101", {roles.LIBRARY_USER.external_key}),
        ("liam", "lib:Org4:art_101", {roles.LIBRARY_AUTHOR.external_key}),
        ("liam", "lib:Org4:art_201", {roles.LIBRARY_AUTHOR.external_key}),
        ("liam", "lib:Org4:art_301", {roles.LIBRARY_AUTHOR.external_key}),
        ("maya", "lib:Org5:economics_101", {roles.LIBRARY_ADMIN.external_key}),
        ("noah", "lib:Org5:economics_101", {roles.LIBRARY_CONTRIBUTOR.external_key}),
        ("olivia", "lib:Org5:economics_101", {roles.LIBRARY_USER.external_key}),
        ("peter", "lib:Org6:project_alpha", {roles.LIBRARY_ADMIN.external_key}),
        ("peter", "lib:Org6:project_beta", {roles.LIBRARY_AUTHOR.external_key}),
        ("peter", "lib:Org6:project_gamma", {roles.LIBRARY_CONTRIBUTOR.external_key}),
        ("peter", "lib:Org6:project_delta", {roles.LIBRARY_USER.external_key}),
        ("non_existent_user", "lib:Org1:math_101", set()),
        ("alice", "lib:Org999:non_existent_scope", set()),
        ("non_existent_user", "lib:Org999:non_existent_scope", set()),
    )
    @unpack
    def test_get_subject_role_assignments_in_scope(self, subject_name, scope_name, expected_roles):
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
                    external_key=roles.LIBRARY_ADMIN.external_key,
                    permissions=LIBRARY_ADMIN_PERMISSIONS,
                ),
            ],
        ),
        (
            "eve",
            [
                RoleData(
                    external_key=roles.LIBRARY_ADMIN.external_key,
                    permissions=LIBRARY_ADMIN_PERMISSIONS,
                ),
                RoleData(
                    external_key=roles.LIBRARY_AUTHOR.external_key,
                    permissions=LIBRARY_AUTHOR_PERMISSIONS,
                ),
                RoleData(
                    external_key=roles.LIBRARY_USER.external_key,
                    permissions=LIBRARY_USER_PERMISSIONS,
                ),
            ],
        ),
        (
            "frank",
            [
                RoleData(
                    external_key=roles.LIBRARY_USER.external_key,
                    permissions=LIBRARY_USER_PERMISSIONS,
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
        role_assignments = get_subject_role_assignments(SubjectData(external_key=subject_name))

        self.assertEqual(len(role_assignments), len(expected_roles))
        for expected_role in expected_roles:
            # Compare the role part of the assignment
            found = any(expected_role in assignment.roles for assignment in role_assignments)
            self.assertTrue(found, f"Expected role {expected_role} not found in assignments")

    @ddt_data(
        (roles.LIBRARY_ADMIN.external_key, "lib:Org1:math_101", 1),
        (roles.LIBRARY_AUTHOR.external_key, "lib:Org1:history_201", 1),
        (roles.LIBRARY_CONTRIBUTOR.external_key, "lib:Org1:science_301", 1),
        (roles.LIBRARY_USER.external_key, "lib:Org1:english_101", 1),
        (roles.LIBRARY_ADMIN.external_key, "lib:Org2:physics_401", 1),
        (roles.LIBRARY_AUTHOR.external_key, "lib:Org2:chemistry_501", 1),
        (roles.LIBRARY_USER.external_key, "lib:Org2:biology_601", 1),
        (roles.LIBRARY_CONTRIBUTOR.external_key, "lib:Org1:math_advanced", 2),
        (roles.LIBRARY_ADMIN.external_key, "lib:Org3:cs_101", 1),
        (roles.LIBRARY_AUTHOR.external_key, "lib:Org3:cs_101", 1),
        (roles.LIBRARY_USER.external_key, "lib:Org3:cs_101", 1),
        (roles.LIBRARY_AUTHOR.external_key, "lib:Org4:art_101", 1),
        (roles.LIBRARY_AUTHOR.external_key, "lib:Org4:art_201", 1),
        (roles.LIBRARY_AUTHOR.external_key, "lib:Org4:art_301", 1),
        (roles.LIBRARY_ADMIN.external_key, "lib:Org5:economics_101", 1),
        (roles.LIBRARY_CONTRIBUTOR.external_key, "lib:Org5:economics_101", 1),
        (roles.LIBRARY_USER.external_key, "lib:Org5:economics_101", 1),
        (roles.LIBRARY_ADMIN.external_key, "lib:Org6:project_alpha", 1),
        (roles.LIBRARY_AUTHOR.external_key, "lib:Org6:project_beta", 1),
        (roles.LIBRARY_CONTRIBUTOR.external_key, "lib:Org6:project_gamma", 1),
        (roles.LIBRARY_USER.external_key, "lib:Org6:project_delta", 1),
        ("non_existent_role", "sc:any_library", 0),
        (roles.LIBRARY_ADMIN.external_key, "sc:non_existent_scope", 0),
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

    @ddt_data(
        # Test case: alice with 'view_library' permission (has library_admin in math_101)
        (
            "alice",
            "view_library",
            ["lib:Org1:math_101"],
        ),
        # Test case: alice with 'publish_library_content' permission (admin grants publish)
        (
            "alice",
            "publish_library_content",
            ["lib:Org1:math_101"],
        ),
        # Test case: alice with 'delete_library' permission (admin grants delete)
        (
            "alice",
            "delete_library",
            ["lib:Org1:math_101"],
        ),
        # Test case: bob with 'view_library' permission (has library_author in history_201)
        (
            "bob",
            "view_library",
            ["lib:Org1:history_201"],
        ),
        # Test case: bob with 'publish_library_content' permission (author grants publish)
        (
            "bob",
            "publish_library_content",
            ["lib:Org1:history_201"],
        ),
        # Test case: bob with 'delete_library' permission (author does NOT grant delete)
        (
            "bob",
            "delete_library",
            [],
        ),
        # Test case: carol with 'view_library' permission (has library_contributor in science_301)
        (
            "carol",
            "view_library",
            ["lib:Org1:science_301"],
        ),
        # Test case: carol with 'publish_library_content' permission (contributor does NOT grant publish)
        (
            "carol",
            "publish_library_content",
            [],
        ),
        # Test case: dave with 'view_library' permission (has library_user in english_101)
        (
            "dave",
            "view_library",
            ["lib:Org1:english_101"],
        ),
        # Test case: dave with 'publish_library_content' permission (user does NOT grant publish)
        (
            "dave",
            "publish_library_content",
            [],
        ),
        # Test case: liam with 'view_library' permission (has library_author in 3 art libraries)
        (
            "liam",
            "view_library",
            ["lib:Org4:art_101", "lib:Org4:art_201", "lib:Org4:art_301"],
        ),
        # Test case: non-existent user
        (
            "nonexistent",
            "view_library",
            [],
        ),
    )
    @unpack
    def test_get_scopes_for_subject_and_permission(self, subject_name, action_name, expected_scope_names):
        """Test retrieving scopes where a subject has a specific permission.

        This tests the get_scopes_for_subject_and_permission function which
        returns all scopes where a subject has been granted a specific permission
        through their role assignments.

        Args:
            subject_name: The external key of the subject (e.g., 'alice')
            action_name: The action to check (e.g., 'view', 'edit', 'delete')
            expected_scope_names: List of expected scope external keys

        Expected result:
            - Returns all scopes where the subject has roles that grant the permission
            - Returns empty list if subject has no roles with that permission
        """
        subject = SubjectData(external_key=subject_name)
        permission = PermissionData(action=ActionData(external_key=action_name))

        scopes = get_scopes_for_subject_and_permission(subject, permission)

        # Extract scope external keys for comparison
        actual_scope_names = [scope.external_key for scope in scopes]

        self.assertEqual(len(actual_scope_names), len(expected_scope_names))
        for expected_scope in expected_scope_names:
            self.assertIn(expected_scope, actual_scope_names)

    @ddt_data(
        (roles.LIBRARY_AUTHOR.external_key, "lib:Org4:art_101", {"liam"}),
        (roles.LIBRARY_AUTHOR.external_key, "lib:Org4:art_201", {"liam"}),
        (roles.LIBRARY_AUTHOR.external_key, "lib:Org4:art_301", {"liam"}),
        ("non_existent_role", "lib:Org4:art_101", set()),
        (roles.LIBRARY_AUTHOR.external_key, "sc:non_existent_scope", set()),
        ("non_existent_role", "sc:non_existent_scope", set()),
    )
    @unpack
    def test_get_subjects_for_role_in_scope(self, role_name: str, scope_name: str, expected_subjects: set[str]):
        """Test retrieving subjects for a given role in a specific scope.

        Expected result:
            - The subjects associated with the specified role in the given scope are correctly retrieved.
        """
        subjects = get_subjects_for_role_in_scope(RoleData(external_key=role_name), ScopeData(external_key=scope_name))

        subject_names = {subject.external_key for subject in subjects}
        self.assertEqual(subject_names, expected_subjects)


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
        (["mary", "john"], roles.LIBRARY_USER.external_key, "sc:batch_test", True),
        (
            ["paul", "diana", "lila"],
            roles.LIBRARY_CONTRIBUTOR.external_key,
            "lib:Org1:math_advanced",
            True,
        ),
        (["sarina", "ty"], roles.LIBRARY_AUTHOR.external_key, "lib:Org4:art_101", True),
        (["fran", "bob"], roles.LIBRARY_ADMIN.external_key, "lib:Org3:cs_101", True),
        (
            ["anna", "tom", "jerry"],
            roles.LIBRARY_USER.external_key,
            "lib:Org1:history_201",
            True,
        ),
        ("joe", roles.LIBRARY_CONTRIBUTOR.external_key, "lib:Org1:science_301", False),
        ("nina", roles.LIBRARY_AUTHOR.external_key, "lib:Org1:english_101", False),
        ("oliver", roles.LIBRARY_ADMIN.external_key, "lib:Org1:math_101", False),
    )
    @unpack
    def test_batch_assign_role_to_subjects_in_scope(self, subject_names, role, scope_name, batch):
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
                    SubjectData(external_key=subject_name),
                    ScopeData(external_key=scope_name),
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
        (["mary", "john"], roles.LIBRARY_USER.external_key, "sc:batch_test", True),
        (
            ["paul", "diana", "lila"],
            roles.LIBRARY_CONTRIBUTOR.external_key,
            "lib:Org1:math_advanced",
            True,
        ),
        (["sarina", "ty"], roles.LIBRARY_AUTHOR.external_key, "lib:Org4:art_101", True),
        (["fran", "bob"], roles.LIBRARY_ADMIN.external_key, "lib:Org3:cs_101", True),
        (
            ["anna", "tom", "jerry"],
            roles.LIBRARY_USER.external_key,
            "lib:Org1:history_201",
            True,
        ),
        ("joe", roles.LIBRARY_CONTRIBUTOR.external_key, "lib:Org1:science_301", False),
        ("nina", roles.LIBRARY_AUTHOR.external_key, "lib:Org1:english_101", False),
        ("oliver", roles.LIBRARY_ADMIN.external_key, "lib:Org1:math_101", False),
    )
    @unpack
    def test_unassign_role_from_subject_in_scope(self, subject_names, role, scope_name, batch):
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
                    roles=[
                        RoleData(
                            external_key=roles.LIBRARY_ADMIN.external_key,
                            permissions=LIBRARY_ADMIN_PERMISSIONS,
                        )
                    ],
                    scope=ScopeData(external_key="lib:Org1:math_101"),
                )
            ],
        ),
        (
            "lib:Org1:history_201",
            [
                RoleAssignmentData(
                    subject=SubjectData(external_key="bob"),
                    roles=[
                        RoleData(
                            external_key=roles.LIBRARY_AUTHOR.external_key,
                            permissions=LIBRARY_AUTHOR_PERMISSIONS,
                        )
                    ],
                    scope=ScopeData(external_key="lib:Org1:history_201"),
                )
            ],
        ),
        (
            "lib:Org1:science_301",
            [
                RoleAssignmentData(
                    subject=SubjectData(external_key="carol"),
                    roles=[
                        RoleData(
                            external_key=roles.LIBRARY_CONTRIBUTOR.external_key,
                            permissions=LIBRARY_CONTRIBUTOR_PERMISSIONS,
                        )
                    ],
                    scope=ScopeData(external_key="lib:Org1:science_301"),
                )
            ],
        ),
        (
            "lib:Org1:english_101",
            [
                RoleAssignmentData(
                    subject=SubjectData(external_key="dave"),
                    roles=[
                        RoleData(
                            external_key=roles.LIBRARY_USER.external_key,
                            permissions=LIBRARY_USER_PERMISSIONS,
                        )
                    ],
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
        role_assignments = get_all_subject_role_assignments_in_scope(ScopeData(external_key=scope_name))

        self.assertEqual(len(role_assignments), len(expected_assignments))
        for assignment in role_assignments:
            self.assertIn(assignment, expected_assignments)
