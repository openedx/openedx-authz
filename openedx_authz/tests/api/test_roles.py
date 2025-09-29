"""Test cases for roles API functions.

In this test suite, we will verify the functionality of the roles API,
including role creation, assignment, permission management, and querying
roles and permissions within specific scopes.
"""

from unittest import TestCase

import casbin
from ddt import data as test_data
from ddt import ddt, unpack

from openedx_authz.api import *
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
        migrate_policy_from_file_to_db(
            source_enforcer=casbin.Enforcer(
                "openedx_authz/engine/config/model.conf",
                "openedx_authz/engine/config/authz.policy",
            ),
            target_enforcer=global_enforcer,
        )

    @classmethod
    def _assign_roles_to_users(
        cls,
        subjects: list[str] | str = [],
        role: str = "",
        scope: str = "",
        batch: bool = False,
        assignments: list[dict] | None = None,
    ):
        """Helper method to assign roles to multiple users.

        This method can be used to assign a role to a single user or multiple users
        in a specific scope. It can also handle batch assignments.

        Args:
            assignments (list of dict): List of assignment dictionaries, each containing:
                - subject (str): ID of the user namespaced (e.g., 'user:john_doe').
                - role_name (str): Name of the role to assign.
                - scope (str): Scope in which to assign the role.
            subjects (list of str or str): List of user IDs or a single user ID to assign the role to.
            role (str): Name of the role to assign.
            scope (str): Scope in which to assign the role.
            batch (bool): If True, assigns the role to multiple subjects in one operation.
        """
        # global_enforcer.load_policy()  # Load policies to avoid duplicates
        if assignments:
            for assignment in assignments:
                assign_role_to_user_in_scope(
                    subject=assignment["subject"],
                    role_name=assignment["role_name"],
                    scope=assignment["scope"],
                )
            # global_enforcer.clear_policy()  # Clear to simulate fresh start for each test
            return

        if batch:
            batch_assign_role_to_subjects_in_scope(
                subjects=subjects,
                role_name=role,
                scope=scope,
            )
            # global_enforcer.clear_policy()  # Clear to simulate fresh start for each test
            return

        assign_role_to_user_in_scope(
            subject=subjects,
            role_name=role,
            scope=scope,
        )
        # global_enforcer.clear_policy()  # Clear to simulate fresh start for each test

    @classmethod
    def setUpClass(cls):
        """Set up test class environment."""
        super().setUpClass()
        # Ensure the database is seeded once for all tests in this class
        assignments = [
            # Basic library roles from authz.policy
            {
                "subject": "user:alice",
                "role_name": "role:library_admin",
                "scope": "lib:math_101",
            },
            {
                "subject": "user:bob",
                "role_name": "role:library_author",
                "scope": "lib:history_201",
            },
            {
                "subject": "user:carol",
                "role_name": "role:library_collaborator",
                "scope": "lib:science_301",
            },
            {
                "subject": "user:dave",
                "role_name": "role:library_user",
                "scope": "lib:english_101",
            },
            # Multi-role assignments - same user with different roles in different libraries
            {
                "subject": "user:eve",
                "role_name": "role:library_admin",
                "scope": "lib:physics_401",
            },
            {
                "subject": "user:eve",
                "role_name": "role:library_author",
                "scope": "lib:chemistry_501",
            },
            {
                "subject": "user:eve",
                "role_name": "role:library_user",
                "scope": "lib:biology_601",
            },
            # Global scope assignments using wildcard
            {
                "subject": "user:frank",
                "role_name": "role:library_user",
                "scope": "lib:any_library",
            },
            # Multiple users with same role in same scope
            {
                "subject": "user:grace",
                "role_name": "role:library_collaborator",
                "scope": "lib:math_advanced",
            },
            {
                "subject": "user:henry",
                "role_name": "role:library_collaborator",
                "scope": "lib:math_advanced",
            },
            # Hierarchical scope assignments - different specificity levels
            {
                "subject": "user:ivy",
                "role_name": "role:library_admin",
                "scope": "lib:cs_101",
            },
            {
                "subject": "user:jack",
                "role_name": "role:library_author",
                "scope": "lib:cs_101",
            },
            {
                "subject": "user:kate",
                "role_name": "role:library_user",
                "scope": "lib:cs_101",
            },
            # Edge case: same user, same role, different scopes
            {
                "subject": "user:liam",
                "role_name": "role:library_author",
                "scope": "lib:art_101",
            },
            {
                "subject": "user:liam",
                "role_name": "role:library_author",
                "scope": "lib:art_201",
            },
            {
                "subject": "user:liam",
                "role_name": "role:library_author",
                "scope": "lib:art_301",
            },
            # Mixed permission levels across libraries for comprehensive testing
            {
                "subject": "user:maya",
                "role_name": "role:library_admin",
                "scope": "lib:economics_101",
            },
            {
                "subject": "user:noah",
                "role_name": "role:library_collaborator",
                "scope": "lib:economics_101",
            },
            {
                "subject": "user:olivia",
                "role_name": "role:library_user",
                "scope": "lib:economics_101",
            },
            # Complex multi-library, multi-role scenario
            {
                "subject": "user:peter",
                "role_name": "role:library_admin",
                "scope": "lib:project_alpha",
            },
            {
                "subject": "user:peter",
                "role_name": "role:library_author",
                "scope": "lib:project_beta",
            },
            {
                "subject": "user:peter",
                "role_name": "role:library_collaborator",
                "scope": "lib:project_gamma",
            },
            {
                "subject": "user:peter",
                "role_name": "role:library_user",
                "scope": "lib:project_delta",
            },
        ]
        cls._seed_database_with_policies()
        cls._assign_roles_to_users(assignments=assignments)

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        # global_enforcer.load_policy()  # Load policies before each test to simulate fresh start

    def tearDown(self):
        """Clean up after each test to ensure isolation."""
        super().tearDown()
        # global_enforcer.clear_policy()  # Clear policies after each test to ensure isolation


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

    @test_data(
        # Library Admin role with actual permissions from authz.policy
        (
            "role:library_admin",
            {
                "role:library_admin": {
                    "permissions": [
                        Permission(name="act:delete_library", effect="allow"),
                        Permission(name="act:publish_library", effect="allow"),
                        Permission(name="act:manage_library_team", effect="allow"),
                        Permission(name="act:manage_library_tags", effect="allow"),
                        Permission(name="act:delete_library_content", effect="allow"),
                        Permission(name="act:publish_library_content", effect="allow"),
                        Permission(
                            name="act:delete_library_collection", effect="allow"
                        ),
                        Permission(name="act:create_library", effect="allow"),
                        Permission(
                            name="act:create_library_collection", effect="allow"
                        ),
                    ],
                    "scopes": ["lib:*"],
                }
            },
        ),
        # Library Author role with actual permissions from authz.policy
        (
            "role:library_author",
            {
                "role:library_author": {
                    "permissions": [
                        Permission(name="act:delete_library_content", effect="allow"),
                        Permission(name="act:publish_library_content", effect="allow"),
                        Permission(name="act:edit_library", effect="allow"),
                        Permission(name="act:manage_library_tags", effect="allow"),
                        Permission(
                            name="act:create_library_collection", effect="allow"
                        ),
                        Permission(name="act:edit_library_collection", effect="allow"),
                        Permission(
                            name="act:delete_library_collection", effect="allow"
                        ),
                    ],
                    "scopes": ["lib:*"],
                }
            },
        ),
        # Library Collaborator role with actual permissions from authz.policy
        (
            "role:library_collaborator",
            {
                "role:library_collaborator": {
                    "permissions": [
                        Permission(name="act:edit_library", effect="allow"),
                        Permission(name="act:delete_library_content", effect="allow"),
                        Permission(name="act:manage_library_tags", effect="allow"),
                        Permission(
                            name="act:create_library_collection", effect="allow"
                        ),
                        Permission(name="act:edit_library_collection", effect="allow"),
                        Permission(
                            name="act:delete_library_collection", effect="allow"
                        ),
                    ],
                    "scopes": ["lib:*"],
                }
            },
        ),
        # Library User role with minimal permissions
        (
            "role:library_user",
            {
                "role:library_user": {
                    "permissions": [
                        Permission(name="act:view_library", effect="allow"),
                        Permission(name="act:view_library_team", effect="allow"),
                        Permission(name="act:reuse_library_content", effect="allow"),
                    ],
                    "scopes": ["lib:*"],
                }
            },
        ),
        # Role in different scope for multi-role user (eve) - this user IS assigned this role in this scope
        (
            "role:library_admin",
            {
                "role:library_admin": {
                    "permissions": [
                        Permission(name="act:delete_library", effect="allow"),
                        Permission(name="act:publish_library", effect="allow"),
                        Permission(name="act:manage_library_team", effect="allow"),
                        Permission(name="act:manage_library_tags", effect="allow"),
                        Permission(name="act:delete_library_content", effect="allow"),
                        Permission(name="act:publish_library_content", effect="allow"),
                        Permission(
                            name="act:delete_library_collection", effect="allow"
                        ),
                        Permission(name="act:create_library", effect="allow"),
                        Permission(
                            name="act:create_library_collection", effect="allow"
                        ),
                    ],
                    "scopes": ["lib:*"],
                }
            },
        ),
        # Non-existent role
        (
            "role:non_existent_role",
            {"role:non_existent_role": {"permissions": [], "scopes": []}},
        ),
        # Empty role list
        # ("", {"": []}), TODO: this returns all roles, is this expected?
        # Non existent role
        (
            "role:non_existent_role",
            {"role:non_existent_role": {"permissions": [], "scopes": []}},
        ),
    )
    @unpack
    def test_get_permissions_for_roles(self, role_name, expected_permissions):
        """Test retrieving permissions for roles in the current environment.

        Expected result:
            - Permissions are correctly retrieved for the given roles and scope.
            - The permissions match the expected permissions.
        """
        assigned_permissions = get_permissions_for_roles([role_name])

        self.assertEqual(assigned_permissions, expected_permissions)

    @test_data(
        # Role assigned to multiple users in different scopes
        (
            "role:library_user",
            "lib:english_101",
            [
                Permission(name="act:view_library", effect="allow"),
                Permission(name="act:view_library_team", effect="allow"),
                Permission(name="act:reuse_library_content", effect="allow"),
            ],
        ),
        # Role assigned to single user in single scope
        (
            "role:library_author",
            "lib:history_201",
            [
                Permission(name="act:delete_library_content", effect="allow"),
                Permission(name="act:publish_library_content", effect="allow"),
                Permission(name="act:edit_library", effect="allow"),
                Permission(name="act:manage_library_tags", effect="allow"),
                Permission(name="act:create_library_collection", effect="allow"),
                Permission(name="act:edit_library_collection", effect="allow"),
                Permission(name="act:delete_library_collection", effect="allow"),
            ],
        ),
        # Role assigned to single user in multiple scopes
        (
            "role:library_admin",
            "lib:math_101",
            [
                Permission(name="act:delete_library", effect="allow"),
                Permission(name="act:publish_library", effect="allow"),
                Permission(name="act:manage_library_team", effect="allow"),
                Permission(name="act:manage_library_tags", effect="allow"),
                Permission(name="act:delete_library_content", effect="allow"),
                Permission(name="act:publish_library_content", effect="allow"),
                Permission(name="act:delete_library_collection", effect="allow"),
                Permission(name="act:create_library", effect="allow"),
                Permission(name="act:create_library_collection", effect="allow"),
            ],
        ),
    )
    @unpack
    def test_get_permissions_for_active_role_in_specific_scope(
        self, role_name, scope, expected_permissions
    ):
        """Test retrieving permissions for a specific role after role assignments.

        Expected result:
            - Permissions are correctly retrieved for the given role.
            - The permissions match the expected permissions for the role.
        """
        assigned_permissions = get_permissions_for_active_roles_in_scope(
            scope, role_name
        )

        self.assertIn(role_name, assigned_permissions)
        self.assertEqual(
            assigned_permissions[role_name]["permissions"],
            expected_permissions,
        )

    @test_data(
        (
            "lib:*",
            {
                "role:library_admin",
                "role:library_author",
                "role:library_collaborator",
                "role:library_user",
            },
        ),
    )
    @unpack
    def test_get_roles_in_scope(self, scope, expected_roles):
        """Test retrieving roles definitions in a specific scope.

        Currently, this function returns all roles defined in the system because
        we're using only lib:* scope. This should be updated when we have more
        (template) scopes in the policy file.

        Expected result:
            - Roles in the given scope are correctly retrieved.
        """
        roles_in_scope = get_role_definitions_in_scope(scope)

        retrieved_role_names = {role.name for role in roles_in_scope}
        self.assertEqual(retrieved_role_names, expected_roles)

    @test_data(
        ("user:alice", "lib:math_101", {"role:library_admin"}),
        ("user:bob", "lib:history_201", {"role:library_author"}),
        ("user:carol", "lib:science_301", {"role:library_collaborator"}),
        ("user:dave", "lib:english_101", {"role:library_user"}),
        ("user:eve", "lib:physics_401", {"role:library_admin"}),
        ("user:eve", "lib:chemistry_501", {"role:library_author"}),
        ("user:eve", "lib:biology_601", {"role:library_user"}),
        ("user:frank", "lib:any_library", {"role:library_user"}),  # Global scope
        ("user:grace", "lib:math_advanced", {"role:library_collaborator"}),
        ("user:henry", "lib:math_advanced", {"role:library_collaborator"}),
        ("user:ivy", "lib:cs_101", {"role:library_admin"}),
        ("user:jack", "lib:cs_101", {"role:library_author"}),
        ("user:kate", "lib:cs_101", {"role:library_user"}),
        ("user:liam", "lib:art_101", {"role:library_author"}),
        ("user:liam", "lib:art_201", {"role:library_author"}),
        ("user:liam", "lib:art_301", {"role:library_author"}),
        ("user:maya", "lib:economics_101", {"role:library_admin"}),
        ("user:noah", "lib:economics_101", {"role:library_collaborator"}),
        ("user:olivia", "lib:economics_101", {"role:library_user"}),
        ("user:peter", "lib:project_alpha", {"role:library_admin"}),
        ("user:peter", "lib:project_beta", {"role:library_author"}),
        ("user:peter", "lib:project_gamma", {"role:library_collaborator"}),
        ("user:peter", "lib:project_delta", {"role:library_user"}),
        ("user:non_existent_user", "lib:math_101", set()),
        ("user:alice", "lib:non_existent_scope", set()),
        ("user:non_existent_user", "lib:non_existent_scope", set()),
    )
    @unpack
    def test_get_roles_for_user_in_scope(self, user, scope, expected_roles):
        """Test retrieving roles assigned to a user in a specific scope.

        Expected result:
            - Roles assigned to the user in the given scope are correctly retrieved.
        """
        user_roles = get_roles_for_subject_in_scope(user, scope)

        role_names = {role.name for role in user_roles}
        self.assertEqual(role_names, expected_roles)

    @test_data(
        (
            "user:alice",
            [
                Role(
                    name="role:library_admin",
                    scopes=["lib:math_101"],
                    permissions=[
                        Permission(name="act:delete_library", effect="allow"),
                        Permission(name="act:publish_library", effect="allow"),
                        Permission(name="act:manage_library_team", effect="allow"),
                        Permission(name="act:manage_library_tags", effect="allow"),
                        Permission(name="act:delete_library_content", effect="allow"),
                        Permission(name="act:publish_library_content", effect="allow"),
                        Permission(
                            name="act:delete_library_collection", effect="allow"
                        ),
                        Permission(name="act:create_library", effect="allow"),
                        Permission(
                            name="act:create_library_collection", effect="allow"
                        ),
                    ],
                ),
            ],
        ),
        (
            "user:eve",
            [
                Role(
                    name="role:library_admin",
                    scopes=["lib:physics_401"],
                    permissions=[
                        Permission(name="act:delete_library", effect="allow"),
                        Permission(name="act:publish_library", effect="allow"),
                        Permission(name="act:manage_library_team", effect="allow"),
                        Permission(name="act:manage_library_tags", effect="allow"),
                        Permission(name="act:delete_library_content", effect="allow"),
                        Permission(name="act:publish_library_content", effect="allow"),
                        Permission(
                            name="act:delete_library_collection", effect="allow"
                        ),
                        Permission(name="act:create_library", effect="allow"),
                        Permission(
                            name="act:create_library_collection", effect="allow"
                        ),
                    ],
                ),
                Role(
                    name="role:library_author",
                    scopes=["lib:chemistry_501"],
                    permissions=[
                        Permission(name="act:delete_library_content", effect="allow"),
                        Permission(name="act:publish_library_content", effect="allow"),
                        Permission(name="act:edit_library", effect="allow"),
                        Permission(name="act:manage_library_tags", effect="allow"),
                        Permission(
                            name="act:create_library_collection", effect="allow"
                        ),
                        Permission(name="act:edit_library_collection", effect="allow"),
                        Permission(
                            name="act:delete_library_collection", effect="allow"
                        ),
                    ],
                ),
                Role(
                    name="role:library_user",
                    scopes=["lib:biology_601"],
                    permissions=[
                        Permission(name="act:view_library", effect="allow"),
                        Permission(name="act:view_library_team", effect="allow"),
                        Permission(name="act:reuse_library_content", effect="allow"),
                    ],
                ),
            ],
        ),
        (
            "user:frank",
            [
                Role(
                    name="role:library_user",
                    scopes=["lib:any_library"],
                    permissions=[
                        Permission(name="act:view_library", effect="allow"),
                        Permission(name="act:view_library_team", effect="allow"),
                        Permission(name="act:reuse_library_content", effect="allow"),
                    ],
                ),
            ],
        ),
        ("user:non_existent_user", []),
    )
    @unpack
    def test_get_all_roles_for_subjects_with_permissions_across_scopes(
        self, subject, expected_roles
    ):
        """Test retrieving all roles assigned to a subject across all scopes.

        Expected result:
            - All roles assigned to the subject across all scopes are correctly retrieved.
            - Each role includes its associated permissions.
        """
        user_roles = get_roles_for_subject(subject, include_permissions=True)

        self.assertEqual(len(user_roles), len(expected_roles))
        for expected_role in expected_roles:
            self.assertIn(expected_role, user_roles)

    @test_data(
        ("role:library_admin", "lib:math_101", 1),
        ("role:library_author", "lib:history_201", 1),
        ("role:library_collaborator", "lib:science_301", 1),
        ("role:library_user", "lib:english_101", 1),
        ("role:library_admin", "lib:physics_401", 1),
        ("role:library_author", "lib:chemistry_501", 1),
        ("role:library_user", "lib:biology_601", 1),
        ("role:library_user", "lib:any_library", 1),  # Global scope
        ("role:library_collaborator", "lib:math_advanced", 2),
        ("role:library_admin", "lib:cs_101", 1),
        ("role:library_author", "lib:cs_101", 1),
        ("role:library_user", "lib:cs_101", 1),
        ("role:library_author", "lib:art_101", 1),
        ("role:library_author", "lib:art_201", 1),
        ("role:library_author", "lib:art_301", 1),
        ("role:library_admin", "lib:economics_101", 1),
        ("role:library_collaborator", "lib:economics_101", 1),
        ("role:library_user", "lib:economics_101", 1),
        ("role:library_admin", "lib:project_alpha", 1),
        ("role:library_author", "lib:project_beta", 1),
        ("role:library_collaborator", "lib:project_gamma", 1),
        ("role:library_user", "lib:project_delta", 1),
        ("role:non_existent_role", "lib:any_library", 0),
        ("role:library_admin", "lib:non_existent_scope", 0),
        ("role:non_existent_role", "lib:non_existent_scope", 0),
    )
    @unpack
    def test_get_role_assignments_in_scope(self, role_name, scope, expected_count):
        """Test retrieving role assignments in a specific scope.

        Expected result:
            - The number of role assignments in the given scope is correctly retrieved.
        """
        role_assignments = get_role_assignments_in_scope(role_name, scope)

        self.assertEqual(len(role_assignments), expected_count)


# @ddt
# class TestRoleAssignmentAPI(RolesTestSetupMixin):
#     """Test cases for role assignment API functions.

#     The enforcer used in these tests cases is the default global enforcer
#     instance from `openedx_authz.engine.enforcer` automatically used by
#     the API to ensure consistency across tests and production environments.

#     In case a different enforcer configuration is needed, consider mocking the
#     enforcer instance in the `openedx_authz.api.roles` module.
#     """

#     @test_data(
#         (["user:mary", "user:john"], "role:library_user", "lib:batch_test", True),
#         (
#             ["user:paul", "user:diana", "user:lila"],
#             "role:library_collaborator",
#             "lib:math_advanced",
#             True,
#         ),
#         (["user:sarina", "user:ty"], "role:library_author", "lib:art_101", True),
#         (["user:fran", "user:bob"], "role:library_admin", "lib:cs_101", True),
#         (
#             ["user:anna", "user:tom", "user:jerry"],
#             "role:library_user",
#             "lib:history_201",
#             True,
#         ),
#         ("user:joe", "role:library_collaborator", "lib:science_301", False),
#         ("user:nina", "role:library_author", "lib:english_101", False),
#         ("user:oliver", "role:library_admin", "lib:math_101", False),
#     )
#     @unpack
#     def test_batch_assign_role_to_subjects_in_scope(self, subjects, role, scope, batch):
#         """Test assigning a role to a single or multiple subjects in a specific scope.

#         Expected result:
#             - Role is successfully assigned to all specified subjects in the given scope.
#             - Each subject has the correct permissions associated with the assigned role.
#             - Each subject can perform actions allowed by the role.
#         """
#         if batch:
#             for subject in subjects:
#                 user_roles = get_roles_for_subject_in_scope(subject, scope)
#                 role_names = {role.name for role in user_roles}
#                 self.assertIn(role, role_names)
#         else:
#             user_roles = get_roles_for_subject_in_scope(subjects, scope)
#             role_names = {role.name for role in user_roles}
#             self.assertIn(role, role_names)

#     @test_data(
#         (["user:mary", "user:john"], "role:library_user", "lib:batch_test", True),
#         (
#             ["user:paul", "user:diana", "user:lila"],
#             "role:library_collaborator",
#             "lib:math_advanced",
#             True,
#         ),
#         (["user:sarina", "user:ty"], "role:library_author", "lib:art_101", True),
#         (["user:fran", "user:bob"], "role:library_admin", "lib:cs_101", True),
#         (
#             ["user:anna", "user:tom", "user:jerry"],
#             "role:library_user",
#             "lib:history_201",
#             True,
#         ),
#         ("user:joe", "role:library_collaborator", "lib:science_301", False),
#         ("user:nina", "role:library_author", "lib:english_101", False),
#         ("user:oliver", "role:library_admin", "lib:math_101", False),
#     )
#     @unpack
#     def test_unassign_role_from_subject_in_scope(self, subjects, role, scope, batch):
#         """Test unassigning a role from a subject or multiple subjects in a specific scope.

#         Expected result:
#             - Role is successfully unassigned from the subject in the specified scope.
#             - Subject no longer has permissions associated with the unassigned role.
#             - The subject cannot perform actions that were allowed by the role.
#         """
#         if batch:
#             for subject in subjects:
#                 unassign_role_from_subject_in_scope(subject, role, scope)
#                 user_roles = get_roles_for_subject_in_scope(subject, scope)
#                 role_names = {role.name for role in user_roles}
#                 self.assertNotIn(role, role_names)
#         else:
#             unassign_role_from_subject_in_scope(subjects, role, scope)
#             user_roles = get_roles_for_subject_in_scope(subjects, scope)
#             role_names = {role.name for role in user_roles}
#             self.assertNotIn(role, role_names)
