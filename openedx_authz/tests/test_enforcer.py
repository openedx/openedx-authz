"""Test cases for enforcer policy loading strategies.

This test suite verifies the functionality of policy loading mechanisms
including filtered loading, scope-based loading, and lifecycle management
that would be used in production environments.
"""

import casbin
from casbin_adapter.models import CasbinRule
from ddt import data as ddt_data
from ddt import ddt, unpack
from django.test import TestCase

from openedx_authz.engine.enforcer import enforcer as global_enforcer
from openedx_authz.engine.filter import Filter
from openedx_authz.engine.utils import migrate_policy_between_enforcers
from openedx_authz.tests.test_utils import make_action_key, make_role_key, make_scope_key, make_user_key


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


@ddt
class TestFilteredPolicyEnforcement(TestCase):
    """
    Integration tests for filtered policy loading with enforcement decisions.

    These tests verify that after loading filtered policies and role assignments,
    the enforcer can correctly make allow/deny decisions based on what's loaded.
    This ensures filtered loading works end-to-end for scope-based authorization.
    """

    def setUp(self):
        """Set up test environment with enforcer and sample data."""
        super().setUp()
        self.enforcer = global_enforcer
        self.enforcer.clear_policy()

        # Create policy rules with wildcard scope templates (like authz.policy)
        # These define what roles can do in ANY library/course
        CasbinRule.objects.create(
            ptype="p",
            v0=make_role_key("library_admin"),
            v1=make_action_key("edit"),
            v2=make_scope_key("lib", "*"),
            v3="allow"
        )
        CasbinRule.objects.create(
            ptype="p",
            v0=make_role_key("library_admin"),
            v1=make_action_key("delete"),
            v2=make_scope_key("lib", "*"),
            v3="allow"
        )
        CasbinRule.objects.create(
            ptype="p",
            v0=make_role_key("library_user"),
            v1=make_action_key("view"),
            v2=make_scope_key("lib", "*"),
            v3="allow"
        )
        # Create role assignments for specific scope instances
        # These assign users to roles in SPECIFIC libraries
        CasbinRule.objects.create(
            ptype="g",
            v0=make_user_key("alice"),
            v1=make_role_key("library_admin"),
            v2=make_scope_key("lib", "test-lib-1")  # Specific instance
        )
        CasbinRule.objects.create(
            ptype="g",
            v0=make_user_key("bob"),
            v1=make_role_key("library_user"),
            v2=make_scope_key("lib", "test-lib-2")  # Specific instance
        )

    def tearDown(self):
        """Clean up after test."""
        self.enforcer.clear_policy()
        super().tearDown()

    def test_enforcement_with_filtered_scope_allows_action(self):
        """Test that filtering by scope allows correct enforcement decisions.

        When loading policies for a specific scope with role assignments,
        users should be allowed to perform actions defined in that scope.

        Expected result:
            - Alice can edit in test-lib-1 (her scope, her permission)
            - Alice can delete in test-lib-1 (her scope, her permission)
        """
        # Load policies and role assignments for test-lib-1 scope
        scope_filter = Filter(
            v2=[
                make_scope_key("lib", "test-lib-1"),
                make_scope_key("lib", "*"),  # Load wildcard policies too
            ],
        )
        self.enforcer.load_filtered_policy(scope_filter)

        # Alice should be allowed to edit in test-lib-1
        result = self.enforcer.enforce(
            make_user_key("alice"),
            make_action_key("edit"),
            make_scope_key("lib", "test-lib-1")
        )
        self.assertTrue(result)

        # Alice should be allowed to delete in test-lib-1
        result = self.enforcer.enforce(
            make_user_key("alice"),
            make_action_key("delete"),
            make_scope_key("lib", "test-lib-1")
        )
        self.assertTrue(result)

    def test_enforcement_with_filtered_scope_denies_out_of_scope(self):
        """Test that filtering by scope denies actions outside the loaded scope.

        When only loading policies for one specific scope instance, actions in
        other scope instances should be denied even if the user has roles there.
        Note: Since policies use wildcards (lib^*), we filter by specific instances
        in the role assignments.

        Expected result:
            - Alice cannot view in test-lib-2 (role assignment not loaded)
            - Bob's actions are not allowed (his role assignment not loaded)
        """
        # Load only test-lib-1 scope (alice's role assignment + wildcard policies)
        scope_filter = Filter(v2=[make_scope_key("lib", "test-lib-1")])
        self.enforcer.load_filtered_policy(scope_filter)

        # Alice should NOT be allowed to act in test-lib-2 (role assignment not loaded)
        result = self.enforcer.enforce(
            make_user_key("alice"),
            make_action_key("view"),
            make_scope_key("lib", "test-lib-2")
        )
        self.assertFalse(result)

        # Bob should NOT be allowed (his role assignment not loaded)
        result = self.enforcer.enforce(
            make_user_key("bob"),
            make_action_key("view"),
            make_scope_key("lib", "test-lib-2")
        )
        self.assertFalse(result)

    def test_enforcement_with_multiple_scopes_loaded(self):
        """Test enforcement when multiple scopes are loaded.

        When loading policies for multiple scopes, users should have
        access according to their roles in each loaded scope.

        Expected result:
            - Alice can edit in test-lib-1
            - Bob can view in test-lib-2
            - Alice cannot view in test-lib-2 (no role there)
            - Bob cannot edit in test-lib-1 (no role there)
        """
        scope_filter = Filter(v2=[
            make_scope_key("lib", "test-lib-1"),
            make_scope_key("lib", "test-lib-2"),
            make_scope_key("lib", "*"),  # Load wildcard policies too to load definitions
        ])
        self.enforcer.load_filtered_policy(scope_filter)

        # Alice can edit in test-lib-1
        self.assertTrue(self.enforcer.enforce(
            make_user_key("alice"),
            make_action_key("edit"),
            make_scope_key("lib", "test-lib-1")
        ))

        # Bob can view in test-lib-2
        self.assertTrue(self.enforcer.enforce(
            make_user_key("bob"),
            make_action_key("view"),
            make_scope_key("lib", "test-lib-2")
        ))

        # Alice cannot view in test-lib-2 (no role assignment)
        self.assertFalse(self.enforcer.enforce(
            make_user_key("alice"),
            make_action_key("view"),
            make_scope_key("lib", "test-lib-2")
        ))

        # Bob cannot edit in test-lib-1 (no role assignment)
        self.assertFalse(self.enforcer.enforce(
            make_user_key("bob"),
            make_action_key("edit"),
            make_scope_key("lib", "test-lib-1")
        ))

    def test_enforcement_without_grouping_policy_denies(self):
        """Test that loading only policies without role assignments denies access.

        When only loading 'p' type policies without 'g' grouping policies,
        users cannot access anything because role assignments aren't loaded.
        Note: We filter by wildcard scope since that's what's in the policies.

        Expected result:
            - Alice cannot edit even though the policy exists
            - No users can perform any actions
        """
        # Load only 'p' type policies with wildcard scope, no role assignments
        policy_filter = Filter(ptype=["p"], v2=[make_scope_key("lib", "*")])
        self.enforcer.load_filtered_policy(policy_filter)

        # Alice should NOT be allowed (no role assignment loaded)
        result = self.enforcer.enforce(
            make_user_key("alice"),
            make_action_key("edit"),
            make_scope_key("lib", "test-lib-1")
        )
        self.assertFalse(result)

    def test_enforcement_with_only_grouping_policy_denies(self):
        """Test that loading only role assignments without policies denies access.

        When only loading 'g' type grouping policies without 'p' policies,
        users cannot access anything because the permissions aren't defined.

        Expected result:
            - Alice cannot edit even though she has the role assignment
        """
        # Load only 'g' type grouping policies, no permission policies
        grouping_filter = Filter(ptype=["g"], v2=[make_scope_key("lib", "test-lib-1")])
        self.enforcer.load_filtered_policy(grouping_filter)

        # Alice should NOT be allowed (no permission policies loaded)
        result = self.enforcer.enforce(
            make_user_key("alice"),
            make_action_key("edit"),
            make_scope_key("lib", "test-lib-1")
        )
        self.assertFalse(result)

    # TODO: add tests for global scopes once supported


@ddt
class TestUserContextPolicyLoading(TestCase):
    """
    Tests for loading policies in a user-specific context.

    These tests demonstrate strategies for loading only the policies relevant
    to a specific user, which is a common production scenario for optimizing
    memory usage and performance in multi-tenant applications.
    """

    def setUp(self):
        """Set up test environment with user-specific policy data."""
        super().setUp()
        self.enforcer = global_enforcer
        self.enforcer.clear_policy()

        CasbinRule.objects.create(
            ptype="p",
            v0=make_role_key("library_admin"),
            v1=make_action_key("edit"),
            v2=make_scope_key("lib", "*"),
            v3="allow"
        )
        CasbinRule.objects.create(
            ptype="p",
            v0=make_role_key("library_admin"),
            v1=make_action_key("delete"),
            v2=make_scope_key("lib", "*"),
            v3="allow"
        )
        CasbinRule.objects.create(
            ptype="p",
            v0=make_role_key("library_user"),
            v1=make_action_key("view"),
            v2=make_scope_key("lib", "*"),
            v3="allow"
        )
        CasbinRule.objects.create(
            ptype="p",
            v0=make_role_key("course_instructor"),
            v1=make_action_key("manage"),
            v2=make_scope_key("course", "*"),
            v3="allow"
        )

        CasbinRule.objects.create(
            ptype="g",
            v0=make_user_key("alice"),
            v1=make_role_key("library_admin"),
            v2=make_scope_key("lib", "alice-lib")
        )
        CasbinRule.objects.create(
            ptype="g",
            v0=make_user_key("alice"),
            v1=make_role_key("course_instructor"),
            v2=make_scope_key("course", "alice-course")
        )
        CasbinRule.objects.create(
            ptype="g",
            v0=make_user_key("bob"),
            v1=make_role_key("library_user"),
            v2=make_scope_key("lib", "bob-lib")
        )

    def tearDown(self):
        """Clean up after test."""
        self.enforcer.clear_policy()
        super().tearDown()

    def test_load_user_context_by_scope(self):
        """Test loading policies for a user by their accessible scopes.

        This is the simplest approach: if you know which scopes a user
        can access, filter by those scopes to load all relevant policies
        and role assignments. Must include both wildcard template and specific scope.

        Expected result:
            - Only library-related policies are loaded
            - Alice can edit in her library scope
            - Alice cannot manage courses (not loaded)
        """
        # Load library policies: both the template (lib^*) and alice's specific scope
        user_scopes = [make_scope_key("lib", "*"), make_scope_key("lib", "alice-lib")]
        scope_filter = Filter(v2=user_scopes)
        self.enforcer.load_filtered_policy(scope_filter)

        # Alice should be able to edit in her library
        self.assertTrue(self.enforcer.enforce(
            make_user_key("alice"),
            make_action_key("edit"),
            make_scope_key("lib", "alice-lib")
        ))

        # Alice should NOT be able to manage courses (not loaded)
        self.assertFalse(self.enforcer.enforce(
            make_user_key("alice"),
            make_action_key("manage"),
            make_scope_key("course", "alice-course")
        ))

    def test_load_multiple_users_in_shared_scope(self):
        """Test loading policies for multiple users in a shared scope.

        When multiple users share access to the same scope, loading
        by scope is more efficient than loading per-user. Must include
        both wildcard template and specific scopes.

        Expected result:
            - All users in the library scope are loaded
            - Each user has appropriate access based on their roles
        """
        # Load all library policies: template and specific instances
        lib_filter = Filter(v2=[
            make_scope_key("lib", "*"),  # Policy template
            make_scope_key("lib", "alice-lib"),  # Alice's role assignment
            make_scope_key("lib", "bob-lib"),  # Bob's role assignment
        ])
        self.enforcer.load_filtered_policy(lib_filter)

        # Both alice and bob should have access based on their roles
        self.assertTrue(self.enforcer.enforce(
            make_user_key("alice"),
            make_action_key("edit"),
            make_scope_key("lib", "alice-lib")
        ))

        self.assertTrue(self.enforcer.enforce(
            make_user_key("bob"),
            make_action_key("view"),
            make_scope_key("lib", "bob-lib")
        ))

    def test_load_user_specific_scope_policies(self):
        """Test loading policies for specific user-scope combination.

        This is useful when you want to load only the policies for a user
        in a specific scope they're currently working in. Must include
        both wildcard template and specific scope.

        Expected result:
            - Only alice's library policies are loaded
            - Alice's course policies are not loaded
            - Bob's library policies are not loaded
        """
        # Load alice's library scope: template + specific scope
        alice_lib_filter = Filter(v2=[
            make_scope_key("lib", "*"),  # Policy template
            make_scope_key("lib", "alice-lib")  # Alice's role assignment
        ])
        self.enforcer.load_filtered_policy(alice_lib_filter)

        # Alice can act in her library
        self.assertTrue(self.enforcer.enforce(
            make_user_key("alice"),
            make_action_key("edit"),
            make_scope_key("lib", "alice-lib")
        ))

        # Alice cannot act in courses (not loaded)
        self.assertFalse(self.enforcer.enforce(
            make_user_key("alice"),
            make_action_key("manage"),
            make_scope_key("course", "alice-course")
        ))

        # Bob cannot act in his library (not loaded)
        self.assertFalse(self.enforcer.enforce(
            make_user_key("bob"),
            make_action_key("view"),
            make_scope_key("lib", "bob-lib")
        ))

    @ddt_data(
        # (user, scopes_to_load, expected_accessible_scopes)
        (
            make_user_key("alice"),
            [make_scope_key("lib", "alice-lib")],
            {make_scope_key("lib", "alice-lib")}
        ),
        (
            make_user_key("alice"),
            [make_scope_key("lib", "alice-lib"), make_scope_key("course", "alice-course")],
            {make_scope_key("lib", "alice-lib"), make_scope_key("course", "alice-course")}
        ),
        (
            make_user_key("bob"),
            [make_scope_key("lib", "bob-lib")],
            {make_scope_key("lib", "bob-lib")}
        ),
    )
    @unpack
    def test_user_context_loading_scenarios(self, user, scopes_to_load, expected_accessible_scopes):
        """Test various user context loading scenarios.

        This parameterized test verifies that loading policies for different
        user-scope combinations produces the expected access patterns.

        Expected result:
            - User can only access scopes that were loaded
            - User cannot access scopes that were not loaded
        """
        scope_filter = Filter(v2=scopes_to_load)
        self.enforcer.load_filtered_policy(scope_filter)

        all_grouping = self.enforcer.get_grouping_policy()
        user_assignments = [g for g in all_grouping if g[0] == user]

        loaded_scopes = {assignment[2] for assignment in user_assignments}
        self.assertEqual(loaded_scopes, expected_accessible_scopes)
