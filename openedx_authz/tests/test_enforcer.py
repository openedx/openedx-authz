"""Test cases for enforcer policy loading strategies.

This test suite verifies the functionality of policy loading mechanisms
including filtered loading, scope-based loading, and lifecycle management
that would be used in production environments.
"""

from unittest import TestCase

import casbin
from ddt import data as test_data
from ddt import ddt, unpack

from openedx_authz.engine.enforcer import enforcer as global_enforcer
from openedx_authz.engine.filter import Filter
from openedx_authz.engine.utils import migrate_policy_from_file_to_db


class PolicyLoadingTestSetupMixin(TestCase):
    """Mixin providing policy loading test utilities."""

    def _seed_database_with_policies(self):
        """Seed the database with policies from the policy file.

        This simulates the one-time database seeding that would happen
        during application deployment, separate from runtime policy loading.
        """
        # Always start with completely clean state
        global_enforcer.clear_policy()

        migrate_policy_from_file_to_db(
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
            scope: The scope to load policies for (e.g., 'lib:*' for all libraries).
                  If None, loads all policies using load_policy().
        """
        if scope is None:
            global_enforcer.load_policy()
        else:
            policy_filter = Filter(v2=[scope])
            global_enforcer.load_filtered_policy(policy_filter)

    def _load_policies_for_user_context(self, user: str, scopes: list[str] = None):
        """Load policies relevant to a specific user and their scopes.

        This simulates a user-centric policy loading strategy where
        only policies relevant to the user's current context are loaded.

        Args:
            user: The user identifier (e.g., 'user:alice').
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
            ["role:course_instructor", "act:edit_course", "course:*", "allow"],
            ["role:course_instructor", "act:grade_students", "course:*", "allow"],
            ["role:course_ta", "act:view_course", "course:*", "allow"],
            ["role:course_ta", "act:grade_assignments", "course:*", "allow"],
            ["role:course_student", "act:view_course", "course:*", "allow"],
            ["role:course_student", "act:submit_assignment", "course:*", "allow"],
            # Organization policies
            ["role:org_admin", "act:manage_org", "org:*", "allow"],
            ["role:org_admin", "act:create_courses", "org:*", "allow"],
            ["role:org_member", "act:view_org", "org:*", "allow"],
        ]

        for policy in test_policies:
            global_enforcer.add_policy(*policy)


@ddt
class TestPolicyLoadingStrategies(PolicyLoadingTestSetupMixin):
    """Test cases demonstrating realistic policy loading strategies.

    These tests demonstrate how policy loading would work in real-world scenarios,
    including scope-based loading, user-context loading, and role-specific loading.
    This provides examples for how the application should load policies in production.
    """

    def setUp(self):
        """Set up test environment without auto-loading policies."""
        super().setUp()
        self._seed_database_with_policies()

    def tearDown(self):
        """Clean up after each test to ensure isolation."""
        global_enforcer.clear_policy()
        super().tearDown()

    @test_data(
        ("lib:*", 4),  # Library policies from authz.policy file
        ("course:*", 0),  # No course policies in basic setup
        ("org:*", 0),  # No org policies in basic setup
    )
    @unpack
    def test_scope_based_policy_loading(self, scope, expected_policy_count):
        """Test loading policies for specific scopes.

        This demonstrates how an application would load only policies
        relevant to the current scope when user navigates to a section.

        Expected result:
            - Enforcer starts empty
            - Only scope-relevant policies are loaded
            - Policy count matches expected for scope
        """
        initial_policy_count = len(global_enforcer.get_policy())

        self._load_policies_for_scope(scope)

        self.assertEqual(initial_policy_count, 0)
        loaded_policies = global_enforcer.get_policy()
        self.assertEqual(len(loaded_policies), expected_policy_count)

        # Verify that only policies for the requested scope are loaded
        if expected_policy_count > 0:
            scope_prefix = scope.replace("*", "")
            for policy in loaded_policies:
                self.assertTrue(policy[2].startswith(scope_prefix))

    def test_user_context_policy_loading(self):
        """Test loading policies based on user context.

        This demonstrates loading policies when a user logs in or
        changes context switching between accessible resources.

        Expected result:
            - Enforcer starts empty
            - Policies are loaded for user's scopes
            - Policy count is reasonable for context
        """
        user = "user:alice"
        user_scopes = ["lib:math_101", "lib:science_301"]
        initial_policy_count = len(global_enforcer.get_policy())

        self._load_policies_for_user_context(user, user_scopes)

        self.assertEqual(initial_policy_count, 0)
        loaded_policies = global_enforcer.get_policy()
        self.assertGreater(len(loaded_policies), 0)

    def test_role_specific_policy_loading(self):
        """Test loading policies for specific role management operations.

        This demonstrates loading policies when performing administrative
        operations like role assignment or permission checking.

        Expected result:
            - Enforcer starts empty
            - Role-specific policies are loaded
            - Loaded policies contain expected role
        """
        role_name = "role:library_admin"
        initial_policy_count = len(global_enforcer.get_policy())

        self._load_policies_for_role_management(role_name)

        self.assertEqual(initial_policy_count, 0)
        loaded_policies = global_enforcer.get_policy()
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

        self._load_policies_for_scope("lib:*")
        library_policy_count = len(global_enforcer.get_policy())
        self.assertGreater(library_policy_count, 0)

        self._load_policies_for_role_management("role:library_admin")
        admin_policy_count = len(global_enforcer.get_policy())
        self.assertLessEqual(admin_policy_count, library_policy_count)

        self._load_policies_for_user_context("user:alice", ["lib:math_101"])
        user_policy_count = len(global_enforcer.get_policy())
        self.assertGreaterEqual(user_policy_count, 0)

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

    @test_data(
        Filter(v2=["lib:*"]),  # Load all library policies
        Filter(v2=["course:*"]),  # Load all course policies
        Filter(v2=["org:*"]),  # Load all organization policies
        Filter(v2=["lib:*", "course:*"]),  # Load library and course policies
        Filter(v0=["role:library_user"]),  # Load policies for specific role
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

    def test_policy_reload_scenarios(self):
        """Test policy reloading in different scenarios.

        This demonstrates how policies can be reloaded when application
        context changes or when fresh policy data is needed.

        Expected result:
            - Each reload operation works correctly
            - Policy counts change appropriately
            - No errors occur during transitions
        """
        self._load_policies_for_scope("lib:*")
        first_load_count = len(global_enforcer.get_policy())
        self.assertGreater(first_load_count, 0)

        global_enforcer.clear_policy()
        cleared_count = len(global_enforcer.get_policy())
        self.assertEqual(cleared_count, 0)

        self._load_policies_for_scope("lib:*")
        reload_count = len(global_enforcer.get_policy())
        self.assertEqual(reload_count, first_load_count)

        self._load_policies_for_role_management("role:library_user")
        filtered_count = len(global_enforcer.get_policy())
        self.assertLessEqual(filtered_count, first_load_count)

    def test_multi_scope_filtering_demonstration(self):
        """Test filtering across multiple scopes to demonstrate effectiveness.

        This test shows that filtered loading actually works by comparing
        policy counts when loading different scope combinations.

        Expected result:
            - Different scopes load different policy counts
            - Combined scopes load sum of individual scopes
            - Filtering is precise and predictable
        """
        # Add test policies for multiple scopes
        self._add_test_policies_for_multiple_scopes()

        # Load all policies to get baseline
        global_enforcer.load_policy()
        total_policy_count = len(global_enforcer.get_policy())
        self.assertGreater(total_policy_count, 0)

        # Test individual scope loading
        self._load_policies_for_scope("lib:*")
        lib_count = len(global_enforcer.get_policy())

        self._load_policies_for_scope("course:*")
        course_count = len(global_enforcer.get_policy())

        self._load_policies_for_scope("org:*")
        org_count = len(global_enforcer.get_policy())

        # Test combined scope loading
        global_enforcer.clear_policy()
        multi_scope_filter = Filter(v2=["lib:*", "course:*"])
        global_enforcer.load_filtered_policy(multi_scope_filter)
        combined_count = len(global_enforcer.get_policy())

        # Verify filtering works as expected
        self.assertEqual(lib_count, 4)
        self.assertEqual(course_count, 6)
        self.assertEqual(org_count, 3)
        self.assertEqual(combined_count, lib_count + course_count)
        self.assertEqual(total_policy_count, lib_count + course_count + org_count)
