"""Test cases for enforcer policy loading strategies.

This test suite verifies the functionality of policy loading mechanisms
including filtered loading, scope-based loading, and lifecycle management
that would be used in production environments.
"""

import time
from unittest.mock import patch

import casbin
from ddt import data as ddt_data
from ddt import ddt
from django.conf import settings
from django.test import TestCase, TransactionTestCase, override_settings

from openedx_authz.engine.enforcer import AuthzEnforcer
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
        global_enforcer = AuthzEnforcer.get_enforcer()
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
        global_enforcer = AuthzEnforcer.get_enforcer()
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
        global_enforcer = AuthzEnforcer.get_enforcer()
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
        global_enforcer = AuthzEnforcer.get_enforcer()
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
        global_enforcer = AuthzEnforcer.get_enforcer()
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
        "role^library_contributor",
    ]

    def setUp(self):
        """Set up test environment without auto-loading policies."""
        super().setUp()
        self._seed_database_with_policies()

    def tearDown(self):
        """Clean up after each test to ensure isolation."""
        AuthzEnforcer.get_enforcer().clear_policy()
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
        global_enforcer = AuthzEnforcer.get_enforcer()
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
        global_enforcer = AuthzEnforcer.get_enforcer()
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
        global_enforcer = AuthzEnforcer.get_enforcer()
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
        global_enforcer = AuthzEnforcer.get_enforcer()
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
        global_enforcer = AuthzEnforcer.get_enforcer()
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
        global_enforcer = AuthzEnforcer.get_enforcer()
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
        global_enforcer = AuthzEnforcer.get_enforcer()
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
        global_enforcer = AuthzEnforcer.get_enforcer()
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
        global_enforcer = AuthzEnforcer.get_enforcer()
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


class TestAutoLoadPolicy(TransactionTestCase):
    """Test cases for auto-load policy functionality.

    Uses TransactionTestCase to avoid database locking issues with SQLite
    when testing concurrent access patterns.
    """

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        AuthzEnforcer._enforcer = None  # pylint: disable=protected-access

    def _seed_database_with_policies(self):
        """Seed the database with policies from the policy file."""
        global_enforcer = AuthzEnforcer.get_enforcer()
        global_enforcer.clear_policy()

        migrate_policy_between_enforcers(
            source_enforcer=casbin.Enforcer(
                "openedx_authz/engine/config/model.conf",
                "openedx_authz/engine/config/authz.policy",
            ),
            target_enforcer=global_enforcer,
        )
        global_enforcer.clear_policy()

    def _wait_for_auto_load(self) -> None:
        """Wait for one auto-load cycle plus a small buffer.

        This uses the configured interval plus a buffer to ensure
        the auto-load has completed.
        """
        interval = settings.CASBIN_AUTO_LOAD_POLICY_INTERVAL
        # Add 50% buffer to ensure auto-load completes
        time.sleep(interval * 1.5)

    @override_settings(CASBIN_AUTO_LOAD_POLICY_INTERVAL=0.5)
    def test_auto_load_policy_detects_changes(self):
        """Test that policy changes are automatically detected without manual reload.

        This test verifies that the SyncedEnforcer's auto-load functionality
        works correctly by:
        1. Setting a short auto-load interval (0.5 seconds)
        2. Seeding the database with policies
        3. Waiting for auto-load to populate the enforcer
        4. Adding a new policy via add_policy() (auto-saved to DB)
        5. Waiting for auto-load to detect and load the change
        6. Adding a role assignment via add_role_for_user_in_domain()
        7. Verifying both changes appear without manual reload

        Expected result:
            - Seeded policies are automatically loaded from database
            - New policies added via add_policy() appear after auto-load interval
            - Role assignments added via add_role_for_user_in_domain() appear after auto-load interval
            - No explicit load_policy() calls are needed
        """
        global_enforcer = AuthzEnforcer.get_enforcer()
        self._seed_database_with_policies()

        # Initial policy count should be 0
        initial_policy_count = len(global_enforcer.get_policy())
        self.assertEqual(initial_policy_count, 0)
        self._wait_for_auto_load()

        # After auto-load, the default policies should be loaded
        policies_after_auto_load = global_enforcer.get_policy()
        self.assertGreater(len(policies_after_auto_load), initial_policy_count)

        # Add a new policy
        new_policy = [
            make_role_key("fake_role"),
            make_action_key("fake_action"),
            make_scope_key("lib", "*"),
            "allow",
        ]
        global_enforcer.add_policy(*new_policy)
        self._wait_for_auto_load()

        # After auto-load, the new policy should be loaded
        policies_after_auto_load = global_enforcer.get_policy()
        self.assertIn(new_policy, policies_after_auto_load)

        # Add a new role assignment
        new_assignment = [
            make_user_key("fake_user"),
            make_role_key("fake_role"),
            make_scope_key("lib", "lib:FakeOrg:FAKELIB"),
        ]
        global_enforcer.add_role_for_user_in_domain(*new_assignment)
        self._wait_for_auto_load()

        # After auto-load, the new role assignment should be loaded
        policies_after_auto_load = global_enforcer.get_grouping_policy()
        self.assertIn(new_assignment, policies_after_auto_load)

    @override_settings(CASBIN_AUTO_LOAD_POLICY_INTERVAL=0)
    def test_auto_load_disabled(self):
        """Test that auto-load can be disabled while auto-save remains enabled.

        This test verifies that when CASBIN_AUTO_LOAD_POLICY_INTERVAL is 0,
        the enforcer does NOT automatically load policies, but auto-save
        works normally for manual operations.

        Expected result:
            - Policies remain empty initially (no auto-load)
            - Policies can be seeded to database (auto-save works)
            - Manual load_policy() loads policies from database
        """
        global_enforcer = AuthzEnforcer.get_enforcer()

        initial_policy_count = len(global_enforcer.get_policy())
        self.assertEqual(initial_policy_count, 0)

        with self.assertNumQueries(0):
            time.sleep(1.0)
            policies_after_wait = global_enforcer.get_policy()
            self.assertEqual(len(policies_after_wait), 0)

        self._seed_database_with_policies()

        with self.assertNumQueries(1):
            time.sleep(1.0)
            global_enforcer.load_policy()
            policies_after_manual_load = global_enforcer.get_policy()
            self.assertGreater(len(policies_after_manual_load), 0)


class TestEnforcerToggleBehavior(TransactionTestCase):
    """Test cases for enforcer behavior with libraries_v2_enabled toggle.

    These tests verify that the enforcer correctly responds to the
    libraries_v2_enabled toggle state, enabling/disabling auto-save
    and auto-load as appropriate.

    Uses TransactionTestCase to ensure clean state between tests.
    """

    def setUp(self):
        """Set up test environment with clean enforcer state."""
        super().setUp()
        # Reset the singleton enforcer before each test
        AuthzEnforcer._enforcer = None  # pylint: disable=protected-access

    def tearDown(self):
        """Clean up enforcer state after test."""
        if AuthzEnforcer._enforcer:  # pylint: disable=protected-access
            try:
                AuthzEnforcer.deactivate_enforcer()
            except Exception:  # pylint: disable=broad-exception-caught
                pass
        AuthzEnforcer._enforcer = None  # pylint: disable=protected-access
        super().tearDown()

    @patch("openedx_authz.engine.enforcer.libraries_v2_enabled")
    @override_settings(CASBIN_AUTO_LOAD_POLICY_INTERVAL=0)
    def test_enforcer_auto_save_enabled_when_toggle_enabled(self, mock_toggle):
        """Test that auto-save is enabled when libraries_v2_enabled toggle is on.

        Expected result:
            - Enforcer is initialized with auto-save enabled
            - Policy changes are persisted to database
            - CASBIN_AUTO_LOAD_POLICY_INTERVAL=0 doesn't disable auto-save
        """
        mock_toggle.is_enabled.return_value = True

        enforcer = AuthzEnforcer.get_enforcer()

        self.assertTrue(AuthzEnforcer.is_auto_save_enabled())

        test_policy = [
            make_role_key("test_role"),
            make_action_key("test_action"),
            make_scope_key("lib", "*"),
            "allow",
        ]
        enforcer.add_policy(*test_policy)

        enforcer.load_policy()
        policies = enforcer.get_policy()

        self.assertIn(test_policy, policies)

    @patch("openedx_authz.engine.enforcer.libraries_v2_enabled")
    @override_settings(CASBIN_AUTO_LOAD_POLICY_INTERVAL=0)
    def test_enforcer_deactivated_when_toggle_disabled(self, mock_toggle):
        """Test that enforcer is deactivated when libraries_v2_enabled toggle is off.

        Expected result:
            - Enforcer is initialized but deactivated
            - Auto-save is disabled via deactivate_enforcer
            - Auto-load is stopped
        """
        mock_toggle.is_enabled.return_value = False

        enforcer = AuthzEnforcer.get_enforcer()

        self.assertFalse(AuthzEnforcer.is_auto_save_enabled())
        self.assertFalse(enforcer.is_auto_loading_running())

    @patch("openedx_authz.engine.enforcer.libraries_v2_enabled")
    @override_settings(CASBIN_AUTO_LOAD_POLICY_INTERVAL=0.5)
    def test_enforcer_auto_load_starts_when_toggle_enabled(self, mock_toggle):
        """Test that auto-load starts when toggle is enabled and interval > 0.

        Expected result:
            - Auto-load thread is started with configured interval
            - Auto-save is enabled
        """
        mock_toggle.is_enabled.return_value = True

        enforcer = AuthzEnforcer.get_enforcer()

        self.assertTrue(enforcer.is_auto_loading_running())
        self.assertTrue(AuthzEnforcer.is_auto_save_enabled())

    @patch("openedx_authz.engine.enforcer.libraries_v2_enabled")
    @override_settings(CASBIN_AUTO_LOAD_POLICY_INTERVAL=0.5)
    def test_enforcer_auto_load_not_restarted_on_subsequent_calls(self, mock_toggle):
        """Test that auto-load is not restarted on subsequent get_enforcer() calls.

        Expected result:
            - Auto-load starts on first call
            - Subsequent calls don't restart the auto-load thread
            - Auto-save remains enabled
        """
        mock_toggle.is_enabled.return_value = True

        enforcer1 = AuthzEnforcer.get_enforcer()
        self.assertTrue(enforcer1.is_auto_loading_running())

        enforcer2 = AuthzEnforcer.get_enforcer()
        self.assertIs(enforcer1, enforcer2)
        self.assertTrue(enforcer2.is_auto_loading_running())
        self.assertTrue(AuthzEnforcer.is_auto_save_enabled())

    @patch("openedx_authz.engine.enforcer.libraries_v2_enabled")
    @override_settings(CASBIN_AUTO_LOAD_POLICY_INTERVAL=0)
    def test_toggle_state_checked_on_every_get_enforcer_call(self, mock_toggle):
        """Test that toggle state is checked on every get_enforcer() call.

        This verifies the "HACK" behavior where the toggle state is
        re-evaluated each time get_enforcer() is called.

        Expected result:
            - First call with toggle off: auto-save disabled
            - Second call with toggle on: auto-save enabled
        """
        mock_toggle.is_enabled.return_value = False
        enforcer1 = AuthzEnforcer.get_enforcer()
        self.assertFalse(AuthzEnforcer.is_auto_save_enabled())

        mock_toggle.is_enabled.return_value = True
        enforcer2 = AuthzEnforcer.get_enforcer()
        self.assertIs(enforcer1, enforcer2)
        self.assertTrue(AuthzEnforcer.is_auto_save_enabled())

    @patch("openedx_authz.engine.enforcer.libraries_v2_enabled")
    @override_settings(CASBIN_AUTO_LOAD_POLICY_INTERVAL=0)
    def test_dummy_toggle_behavior_in_tests(self, mock_toggle):
        """Test enforcer behavior with DummyToggle (CMS not available).

        When CMS is not available, a DummyToggle is used that always
        returns True. This test verifies that the enforcer still works
        correctly in this scenario.

        Expected result:
            - Enforcer initializes successfully
            - Auto-save is enabled (DummyToggle returns True)
        """
        mock_toggle.is_enabled.return_value = True

        enforcer = AuthzEnforcer.get_enforcer()

        self.assertIsNotNone(enforcer)
        self.assertTrue(AuthzEnforcer.is_auto_save_enabled())

    @patch("openedx_authz.engine.enforcer.libraries_v2_enabled")
    @override_settings(CASBIN_AUTO_LOAD_POLICY_INTERVAL=0)
    def test_auto_save_preserved_with_interval_zero(self, mock_toggle):
        """Test that auto-save state is preserved when interval is 0.

        When CASBIN_AUTO_LOAD_POLICY_INTERVAL is 0, calling get_enforcer()
        multiple times should not disable auto-save if it was manually enabled.

        Expected result:
            - Tests can manually enable auto-save
            - Subsequent get_enforcer() calls preserve auto-save state
        """
        mock_toggle.is_enabled.return_value = True

        enforcer = AuthzEnforcer.get_enforcer()
        enforcer.enable_auto_save(True)
        self.assertTrue(AuthzEnforcer.is_auto_save_enabled())

        # Call get_enforcer() again - should not disable auto-save
        enforcer2 = AuthzEnforcer.get_enforcer()
        self.assertIs(enforcer, enforcer2)
        self.assertTrue(AuthzEnforcer.is_auto_save_enabled())

    @patch("openedx_authz.engine.enforcer.libraries_v2_enabled")
    @override_settings(CASBIN_AUTO_LOAD_POLICY_INTERVAL=0)
    def test_auto_save_persistence_with_interval_zero(self, mock_toggle):
        """Test that policies persist to database when auto-save is enabled with interval 0.

        Expected result:
            - Policies added via add_policy() are persisted to database
            - Policies can be reloaded from database
        """
        mock_toggle.is_enabled.return_value = True

        enforcer = AuthzEnforcer.get_enforcer()
        enforcer.enable_auto_save(True)

        test_policy = [
            make_role_key("test_role"),
            make_action_key("test_action"),
            make_scope_key("lib", "*"),
            "allow",
        ]
        enforcer.add_policy(*test_policy)

        # Reload from database
        enforcer.load_policy()
        policies = enforcer.get_policy()

        self.assertIn(test_policy, policies)

    @patch("openedx_authz.engine.enforcer.libraries_v2_enabled")
    @override_settings(CASBIN_AUTO_LOAD_POLICY_INTERVAL=0, CASBIN_AUTO_SAVE_POLICY=False)
    def test_auto_save_disabled_explicitly(self, mock_toggle):
        """Test that auto-save is disabled when CASBIN_AUTO_SAVE_POLICY is False.

        Expected result:
            - Auto-save is disabled
            - Auto-load is not running
        """
        mock_toggle.is_enabled.return_value = True

        enforcer = AuthzEnforcer.get_enforcer()

        self.assertFalse(AuthzEnforcer.is_auto_save_enabled())
        self.assertFalse(enforcer.is_auto_loading_running())

    @patch("openedx_authz.engine.enforcer.libraries_v2_enabled")
    @override_settings(CASBIN_AUTO_LOAD_POLICY_INTERVAL=0, CASBIN_AUTO_SAVE_POLICY=False)
    def test_policies_not_persisted_when_auto_save_disabled(self, mock_toggle):
        """Test that policies don't persist when auto-save is explicitly disabled.

        Expected result:
            - Policies added are only in memory
            - Reloading from database clears them
        """
        mock_toggle.is_enabled.return_value = True

        enforcer = AuthzEnforcer.get_enforcer()

        test_policy = [
            make_role_key("test_role"),
            make_action_key("test_action"),
            make_scope_key("lib", "*"),
            "allow",
        ]
        enforcer.add_policy(*test_policy)

        # Policy should be in memory
        self.assertIn(test_policy, enforcer.get_policy())

        # Reload from database - should clear memory-only policy
        enforcer.load_policy()
        policies = enforcer.get_policy()

        self.assertNotIn(test_policy, policies)

    @patch("openedx_authz.engine.enforcer.libraries_v2_enabled")
    @override_settings(CASBIN_AUTO_LOAD_POLICY_INTERVAL=0)
    def test_multiple_get_enforcer_calls_preserve_auto_save(self, mock_toggle):
        """Test that multiple get_enforcer() calls don't repeatedly disable auto-save.

        This is a regression test for the bug where get_enforcer() would
        disable auto-save on every call when interval was 0.

        Expected result:
            - After manually enabling auto-save, it stays enabled
            - Multiple get_enforcer() calls don't change auto-save state
        """
        mock_toggle.is_enabled.return_value = True

        # First call
        enforcer1 = AuthzEnforcer.get_enforcer()
        enforcer1.enable_auto_save(True)
        self.assertTrue(AuthzEnforcer.is_auto_save_enabled())

        # Multiple subsequent calls
        for _ in range(5):
            AuthzEnforcer.get_enforcer()
            self.assertTrue(AuthzEnforcer.is_auto_save_enabled())
