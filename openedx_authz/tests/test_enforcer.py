"""Test cases for enforcer policy loading strategies.

This test suite verifies the functionality of policy loading mechanisms
including filtered loading, scope-based loading, and lifecycle management
that would be used in production environments.
"""

import casbin
from ddt import data as ddt_data
from ddt import ddt
from django.test import TestCase

from openedx_authz.engine.enforcer import enforcer as global_enforcer
from openedx_authz.engine.filter import Filter
from openedx_authz.engine.utils import migrate_policy_between_enforcers


class PolicyLoadingTestSetupMixin(TestCase):
    """Mixin providing policy loading test utilities."""

    @staticmethod
    def _count_policies_in_file(scope_pattern: str = None, role: str = None):
        """Count policies in the authz.policy file matching the given criteria.

        This provides a dynamic way to get expected policy counts without
        hardcoding values that might change as the policy file evolves.

        Args:
            scope_pattern: Scope pattern to match (e.g., 'lib^*')
            role: Role to match (e.g., 'role^library_admin')

        Returns:
            int: Number of matching policies
        """
        count = 0
        with open("openedx_authz/engine/config/authz.policy", "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if not line.startswith("p,"):
                    continue

                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 4:
                    continue

                # parts[0] = 'p', parts[1] = role, parts[2] = action, parts[3] = scope
                matches = True
                if role and parts[1] != role:
                    matches = False
                if scope_pattern and parts[3] != scope_pattern:
                    matches = False

                if matches:
                    count += 1
        return count

    def _seed_database_with_policies(self):
        """Seed the database with policies from the policy file.

        This simulates the one-time database seeding that would happen
        during application deployment, separate from runtime policy loading.
        """
        # Always start with completely clean state
        global_enforcer.clear_policy()

        migrate_policy_between_enforcers(
            source_enforcer=casbin.Enforcer(
                "openedx_authz/engine/config/model.conf",
                "openedx_authz/engine/config/authz.policy",
            ),
            target_enforcer=global_enforcer,
        )
        # Ensure enforcer memory is clean for test isolation
        global_enforcer.clear_policy()

    def _load_policies_for_scope(self, scope: str = None):
        """Load policies for a specific scope using load_filtered_policy.

        This simulates the real-world scenario where the application
        loads only relevant policies based on the current context.

        Args:
            scope: The scope to load policies for (e.g., 'lib^*' for all libraries).
                  If None, loads all policies using load_policy().
        """
        if scope is None:
            global_enforcer.load_policy()
        else:
            policy_filter = Filter(v2=[scope])
            global_enforcer.load_filtered_policy(policy_filter)

    def _load_policies_for_user_context(self, scopes: list[str] = None):
        """Load policies relevant to a user's context like accessible scopes.

        Args:
            scopes: List of scopes the user is operating in.
        """
        global_enforcer.clear_policy()

        if scopes:
            scope_filter = Filter(v2=scopes)
            global_enforcer.load_filtered_policy(scope_filter)
        else:
            global_enforcer.load_policy()

    def _load_policies_for_role_management(self, role_name: str = None):
        """Load policies needed for role management operations.

        This simulates loading policies when performing role management
        operations like assigning roles, checking permissions, etc.

        Args:
            role_name: Specific role to load policies for, if any.
        """
        global_enforcer.clear_policy()

        if role_name:
            role_filter = Filter(v0=[role_name])
            global_enforcer.load_filtered_policy(role_filter)
        else:
            role_filter = Filter(ptype=["p"])
            global_enforcer.load_filtered_policy(role_filter)

    def _add_test_policies_for_multiple_scopes(self):
        """Add test policies for different scopes to demonstrate filtering.

        This adds course and organization policies in addition to existing
        library policies to create a realistic multi-scope environment.
        """
        test_policies = [
            # Course policies
            ["role^course_instructor", "act^edit_course", "course^*", "allow"],
            ["role^course_instructor", "act^grade_students", "course^*", "allow"],
            ["role^course_ta", "act^view_course", "course^*", "allow"],
            ["role^course_ta", "act^grade_assignments", "course^*", "allow"],
            ["role^course_student", "act^view_course", "course^*", "allow"],
            ["role^course_student", "act^submit_assignment", "course^*", "allow"],
            # Organization policies
            ["role^org_admin", "act^manage_org", "org^*", "allow"],
            ["role^org_admin", "act^create_courses", "org^*", "allow"],
            ["role^org_member", "act^view_org", "org^*", "allow"],
        ]

        for policy in test_policies:
            global_enforcer.add_policy(*policy)


@ddt
class TestPolicyLoadingStrategies(PolicyLoadingTestSetupMixin):
    """Test cases demonstrating realistic policy loading strategies.

    These tests demonstrate how policy loading would work in real-world scenarios,
    including scope-based loading, user-context loading, and role-specific loading.
    All based on our basic policy setup in authz.policy file.
    """

    LIBRARY_ROLES = [
        "role^library_user",
        "role^library_admin",
        "role^library_author",
        "role^library_collaborator",
    ]

    def setUp(self):
        """Set up test environment without auto-loading policies."""
        super().setUp()
        self._seed_database_with_policies()

    def tearDown(self):
        """Clean up after each test to ensure isolation."""
        global_enforcer.clear_policy()
        super().tearDown()

    @ddt_data(
        "lib^*",  # Library policies from authz.policy file
        "course^*",  # No course policies in basic setup
        "org^*",  # No org policies in basic setup
    )
    def test_scope_based_policy_loading(self, scope):
        """Test loading policies for specific scopes.

        This demonstrates how an application would load only policies
        relevant to the current scope when user navigates to a section.

        Expected result:
            - Enforcer starts empty
            - Only scope-relevant policies are loaded
            - Policy count matches expected for scope
        """
        expected_policy_count = self._count_policies_in_file(scope_pattern=scope)
        initial_policy_count = len(global_enforcer.get_policy())

        self._load_policies_for_scope(scope)
        loaded_policies = global_enforcer.get_policy()

        self.assertEqual(initial_policy_count, 0)
        self.assertEqual(len(loaded_policies), expected_policy_count)

        if expected_policy_count > 0:
            scope_prefix = scope.replace("*", "")
            for policy in loaded_policies:
                self.assertTrue(policy[2].startswith(scope_prefix))

    @ddt_data(
        ["lib^*"],
        ["lib^*", "course^*"],
        ["org^*"],
    )
    def test_user_context_policy_loading(self, user_scopes):
        """Test loading policies based on user context.

        This demonstrates loading policies when a user logs in or
        changes context switching between accessible resources.

        Expected result:
            - Enforcer starts empty
            - Policies are loaded for user's scopes
            - Policy count is reasonable for context
        """
        initial_policy_count = len(global_enforcer.get_policy())

        self._load_policies_for_user_context(user_scopes)
        loaded_policies = global_enforcer.get_policy()

        self.assertEqual(initial_policy_count, 0)
        self.assertGreaterEqual(len(loaded_policies), 0)

    @ddt_data(*LIBRARY_ROLES)
    def test_role_specific_policy_loading(self, role_name):
        """Test loading policies for specific role management operations.

        This demonstrates loading policies when performing administrative
        operations like role assignment or permission checking.

        Expected result:
            - Enforcer starts empty
            - Role-specific policies are loaded
            - Loaded policies contain expected role
        """
        initial_policy_count = len(global_enforcer.get_policy())

        self._load_policies_for_role_management(role_name)
        loaded_policies = global_enforcer.get_policy()

        self.assertEqual(initial_policy_count, 0)
        self.assertGreater(len(loaded_policies), 0)

        role_found = any(role_name in str(policy) for policy in loaded_policies)
        self.assertTrue(role_found)

    def test_policy_loading_lifecycle(self):
        """Test the complete policy loading lifecycle.

        This demonstrates a realistic sequence of policy loading operations
        that might occur during application runtime.

        Expected result:
            - Each loading stage produces expected policy counts
            - Policy counts change appropriately between stages
            - No policies exist at startup
        """
        startup_policy_count = len(global_enforcer.get_policy())

        self.assertEqual(startup_policy_count, 0)

        self._load_policies_for_scope("lib^*")
        library_policy_count = len(global_enforcer.get_policy())

        self.assertGreater(library_policy_count, 0)

        self._load_policies_for_role_management("role^library_admin")
        admin_policy_count = len(global_enforcer.get_policy())

        self.assertLessEqual(admin_policy_count, library_policy_count)

        self._load_policies_for_user_context(["lib^*"])
        user_policy_count = len(global_enforcer.get_policy())

        self.assertEqual(user_policy_count, library_policy_count)

    def test_empty_enforcer_behavior(self):
        """Test behavior when no policies are loaded.

        This demonstrates what happens when the enforcer has no policies,
        which is the default state in production before explicit loading.

        Expected result:
            - Enforcer starts empty
            - Policy queries return empty results
            - No enforcement decisions are possible
        """
        initial_policy_count = len(global_enforcer.get_policy())
        all_policies = global_enforcer.get_policy()
        all_grouping_policies = global_enforcer.get_grouping_policy()

        self.assertEqual(initial_policy_count, 0)
        self.assertEqual(len(all_policies), 0)
        self.assertEqual(len(all_grouping_policies), 0)

    @ddt_data(
        Filter(v2=["lib^*"]),  # Load all library policies
        Filter(v2=["course^*"]),  # Load all course policies
        Filter(v2=["org^*"]),  # Load all organization policies
        Filter(v2=["lib^*", "course^*"]),  # Load library and course policies
        Filter(v0=["role^library_user"]),  # Load policies for specific role
        Filter(ptype=["p"]),  # Load all 'p' type policies
    )
    def test_filtered_policy_loading_variations(self, policy_filter):
        """Test various filtered policy loading scenarios.

        This demonstrates different filtering strategies that can be used
        to load specific subsets of policies based on application needs.

        Expected result:
            - Enforcer starts empty
            - Filtered loading works without errors
            - Appropriate policies are loaded based on filter
        """
        initial_policy_count = len(global_enforcer.get_policy())

        global_enforcer.clear_policy()
        global_enforcer.load_filtered_policy(policy_filter)

        loaded_policies = global_enforcer.get_policy()

        self.assertEqual(initial_policy_count, 0)
        self.assertGreaterEqual(len(loaded_policies), 0)

    def test_policy_clear_and_reload(self):
        """Test clearing and reloading policies maintains consistency.

        Expected result:
            - Cleared enforcer has no policies
            - Reloading produces same count as initial load
        """
        self._load_policies_for_scope("lib^*")
        initial_load_count = len(global_enforcer.get_policy())

        self.assertGreater(initial_load_count, 0)

        global_enforcer.clear_policy()
        cleared_count = len(global_enforcer.get_policy())

        self.assertEqual(cleared_count, 0)

        self._load_policies_for_scope("lib^*")
        reloaded_count = len(global_enforcer.get_policy())

        self.assertEqual(reloaded_count, initial_load_count)

    @ddt_data(*LIBRARY_ROLES)
    def test_filtered_loading_by_role(self, role_name):
        """Test loading policies filtered by specific role.

        Expected result:
            - Filtered count matches policies in file for that role
            - All loaded policies contain the specified role
        """
        expected_count = self._count_policies_in_file(role=role_name)

        self._load_policies_for_role_management(role_name)
        loaded_policies = global_enforcer.get_policy()

        self.assertEqual(len(loaded_policies), expected_count)

        for policy in loaded_policies:
            self.assertIn(role_name, str(policy))

    def test_multi_scope_filtering(self):
        """Test filtering across multiple scopes.

        Expected result:
            - Combined scope filter loads sum of individual scopes
            - Total load equals sum of all scope policies
        """
        lib_scope = "lib^*"
        course_scope = "course^*"
        org_scope = "org^*"

        expected_lib_count = self._count_policies_in_file(scope_pattern=lib_scope)
        self._add_test_policies_for_multiple_scopes()

        self._load_policies_for_scope(lib_scope)
        lib_count = len(global_enforcer.get_policy())

        self._load_policies_for_scope(course_scope)
        course_count = len(global_enforcer.get_policy())

        self._load_policies_for_scope(org_scope)
        org_count = len(global_enforcer.get_policy())

        self.assertEqual(lib_count, expected_lib_count)
        self.assertEqual(course_count, 6)
        self.assertEqual(org_count, 3)

        global_enforcer.clear_policy()
        combined_filter = Filter(v2=[lib_scope, course_scope])
        global_enforcer.load_filtered_policy(combined_filter)
        combined_count = len(global_enforcer.get_policy())

        self.assertEqual(combined_count, lib_count + course_count)

        global_enforcer.load_policy()
        total_count = len(global_enforcer.get_policy())

        self.assertEqual(total_count, lib_count + course_count + org_count)
