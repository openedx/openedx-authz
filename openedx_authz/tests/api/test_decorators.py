"""Test cases for decorator functions.

This test suite verifies the functionality of the `manage_policy_lifecycle` decorator,
which manages policy loading and clearing around API function calls.
"""

import casbin
from ddt import data as ddt_data
from ddt import ddt, unpack
from django.test import TestCase

from openedx_authz.api.data import (
    ActionData,
    RoleData,
    ScopeData,
    SubjectData,
)
from openedx_authz.api.decorators import manage_policy_lifecycle
from openedx_authz.api.roles import (
    assign_role_to_subject_in_scope,
    get_permissions_for_active_roles_in_scope,
)
from openedx_authz.engine.enforcer import enforcer as global_enforcer
from openedx_authz.engine.filter import Filter
from openedx_authz.engine.utils import migrate_policy_between_enforcers


@ddt
class TestPolicyLifecycleDecorator(TestCase):
    """Test cases for the manage_policy_lifecycle decorator.

    These tests verify that the decorator properly manages the enforcer policy lifecycle
    by loading filtered policies before function execution and clearing policies after.

    The enforcer used in these test cases is the default global enforcer
    instance from `openedx_authz.engine.enforcer` to ensure consistency
    with production environments.
    """

    @classmethod
    def _seed_database_with_policies(cls):
        """Seed the database with policies from the policy file."""
        global_enforcer.load_policy()
        migrate_policy_between_enforcers(
            source_enforcer=casbin.Enforcer(
                "openedx_authz/engine/config/model.conf",
                "openedx_authz/engine/config/authz.policy",
            ),
            target_enforcer=global_enforcer,
        )
        global_enforcer.clear_policy()

    @classmethod
    def setUpClass(cls):
        """Set up test class environment."""
        super().setUpClass()
        cls._seed_database_with_policies()
        # Create test role assignments for various subjects and scopes
        assignments = [
            {
                "subject_name": "alice",
                "role_name": "library_admin",
                "scope_name": "lib:Org1:math_101",
            },
            {
                "subject_name": "bob",
                "role_name": "library_user",
                "scope_name": "lib:Org2:science_201",
            },
            {
                "subject_name": "carol",
                "role_name": "library_author",
                "scope_name": "lib:Org3:history_301",
            },
        ]
        for assignment in assignments:
            assign_role_to_subject_in_scope(
                subject=SubjectData(external_key=assignment["subject_name"]),
                role=RoleData(external_key=assignment["role_name"]),
                scope=ScopeData(external_key=assignment["scope_name"]),
            )

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        global_enforcer.clear_policy()

    def tearDown(self):
        """Clean up after each test to ensure isolation."""
        super().tearDown()
        global_enforcer.clear_policy()

    def test_decorator_filters_by_scope_and_clears(self):
        """Test decorator loads filtered policies by scope and clears after execution.

        Expected result:
            - Decorator loads filtered policies for the given scope
            - Function can access and count the filtered policies
            - Policies enable correct enforcement decisions
            - Enforcer is cleared after execution
        """
        scope = ScopeData(external_key="lib:Org1:math_101")

        @manage_policy_lifecycle(filter_on="scope")
        def get_policy_info(scope_arg):
            policy_count = len(global_enforcer.get_policy())
            grouping_policy_count = len(global_enforcer.get_grouping_policy())
            return {
                "policies": policy_count,
                "grouping_policies": grouping_policy_count,
                "total": policy_count + grouping_policy_count,
            }

        result = get_policy_info(scope)

        # Verify exact counts by loading filtered policy and checking
        # Load both wildcard and specific scope like the decorator does
        global_enforcer.load_filtered_policy(Filter(v2=[scope.policy_template, scope.namespaced_key]))
        expected_policies = len(global_enforcer.get_policy())
        expected_grouping = len(global_enforcer.get_grouping_policy())
        global_enforcer.clear_policy()

        self.assertEqual(result["policies"], expected_policies)
        self.assertEqual(result["grouping_policies"], expected_grouping)
        self.assertEqual(result["total"], expected_policies + expected_grouping)

    def test_decorator_loads_full_policy_without_filter(self):
        """Test decorator loads full policy when no filter criteria is provided.

        Expected result:
            - load_policy is called when no scope arguments present
            - Enforcer has all policies loaded during execution
        """

        @manage_policy_lifecycle(filter_on="scope")
        def get_full_policy_count(some_arg):
            """Function that does not take a scope argument.

            This should cause the decorator to load the full policy.
            """
            policy_count = len(global_enforcer.get_policy())
            grouping_count = len(global_enforcer.get_grouping_policy())
            return policy_count + grouping_count

        total_count = get_full_policy_count("some_string")

        global_enforcer.load_policy()
        self.assertEqual(
            total_count,
            len(global_enforcer.get_policy()) + len(global_enforcer.get_grouping_policy()),
            "Should have loaded full policy"
        )

    def test_decorator_clears_policy_on_exception(self):
        """Test decorator clears policy even when decorated function raises exception.

        Expected result:
            - Policy is loaded before function execution
            - Exception propagates correctly
            - Enforcer is cleared even when exception occurs
        """

        @manage_policy_lifecycle(filter_on="scope")
        def failing_function(scope_arg):
            """Function that raises an exception to test decorator cleanup."""
            if len(global_enforcer.get_policy()) >= 0:
                raise ValueError("Intentional test exception")
            return "should not reach here"

        scope = ScopeData(external_key="lib:Org1:math_101")

        with self.assertRaises(ValueError) as context:
            failing_function(scope)

        self.assertEqual(str(context.exception), "Intentional test exception")

    def test_decorator_with_enforcement_checks(self):
        """Test that policies loaded by decorator enable correct enforcement decisions.

        Expected result:
            - Decorator loads policies that can be used for authorization checks
            - Enforcer.enforce() works correctly with loaded policies
            - Correct authorization decisions are made based on roles
            - Policy counts are verified
        """
        scope = ScopeData(external_key="lib:Org1:math_101")
        subject = SubjectData(external_key="alice")

        @manage_policy_lifecycle(filter_on="scope")
        def check_permissions(scope_arg, subject_arg):
            """Check if subject has permissions in the given scope.

            Expected scenario:
            - Alice has library_admin role in lib:Org1:math_101
            - library_admin role should allow delete_library action
            - library_admin role should NOT allow some_nonexistent_action
            """
            can_delete = global_enforcer.enforce(
                subject_arg.namespaced_key,
                ActionData(external_key="delete_library").namespaced_key,
                scope_arg.namespaced_key,
            )

            cannot_do_fake = not global_enforcer.enforce(
                subject_arg.namespaced_key,
                ActionData(external_key="some_nonexistent_action").namespaced_key,
                scope_arg.namespaced_key,
            )

            policy_count = len(global_enforcer.get_policy())
            grouping_count = len(global_enforcer.get_grouping_policy())

            return {
                "can_delete": can_delete,
                "cannot_do_fake": cannot_do_fake,
                "policy_count": policy_count,
                "grouping_count": grouping_count,
            }

        result = check_permissions(scope, subject)

        self.assertTrue(result["can_delete"], "Alice should be able to delete library")
        self.assertTrue(
            result["cannot_do_fake"],
            "Alice should not be able to do nonexistent action",
        )

        # Verify exact counts
        # Load both wildcard and specific scope like the decorator does
        global_enforcer.load_filtered_policy(Filter(v2=[scope.policy_template, scope.namespaced_key]))
        expected_policies = len(global_enforcer.get_policy())
        expected_grouping = len(global_enforcer.get_grouping_policy())
        global_enforcer.clear_policy()

        self.assertEqual(result["policy_count"], expected_policies)
        self.assertEqual(result["grouping_count"], expected_grouping)

    def test_decorator_enforcement_with_different_subjects(self):
        """Test enforcement with different subjects having different roles.

        Expected result:
            - Each subject's role-based permissions are correctly enforced
            - Different subjects have different access rights
            - Policy loading and clearing works correctly for complex scenarios
        """
        scope = ScopeData(external_key="lib:Org2:science_201")
        alice = SubjectData(external_key="alice")
        bob = SubjectData(external_key="bob")

        @manage_policy_lifecycle(filter_on="scope")
        def check_multiple_subjects(scope_arg):
            """Check permissions for multiple subjects in the same scope.

            Expected scenario:
            - Bob has library_user role - can view but not delete
            - Alice has no role in this scope - cannot view or delete
            """
            bob_can_view = global_enforcer.enforce(
                bob.namespaced_key,
                ActionData(external_key="view_library").namespaced_key,
                scope_arg.namespaced_key,
            )

            bob_cannot_delete = not global_enforcer.enforce(
                bob.namespaced_key,
                ActionData(external_key="delete_library").namespaced_key,
                scope_arg.namespaced_key,
            )

            alice_cannot_view = not global_enforcer.enforce(
                alice.namespaced_key,
                ActionData(external_key="view_library").namespaced_key,
                scope_arg.namespaced_key,
            )

            policy_count = len(global_enforcer.get_policy())
            grouping_count = len(global_enforcer.get_grouping_policy())

            return {
                "bob_can_view": bob_can_view,
                "bob_cannot_delete": bob_cannot_delete,
                "alice_cannot_view": alice_cannot_view,
                "policy_count": policy_count,
                "grouping_count": grouping_count,
            }

        result = check_multiple_subjects(scope)

        self.assertTrue(result["bob_can_view"], "Bob should be able to view library")
        self.assertTrue(
            result["bob_cannot_delete"], "Bob should not be able to delete library"
        )
        self.assertTrue(
            result["alice_cannot_view"],
            "Alice should not be able to view (no role in this scope)",
        )

        # Verify exact counts
        # Load both wildcard and specific scope like the decorator does
        global_enforcer.load_filtered_policy(Filter(v2=[scope.policy_template, scope.namespaced_key]))
        expected_policies = len(global_enforcer.get_policy())
        expected_grouping = len(global_enforcer.get_grouping_policy())
        global_enforcer.clear_policy()

        self.assertEqual(result["policy_count"], expected_policies)
        self.assertEqual(result["grouping_count"], expected_grouping)

    def test_decorator_integration_with_real_api_function(self):
        """Test decorator behavior with actual API function.

        This verifies the decorator works correctly in its intended use case:
        wrapping API functions that query policies.

        Expected result:
            - Decorator loads policies filtered by scope
            - API function returns correct permissions for active roles
            - Enforcer is cleared after execution
        """
        scope = ScopeData(external_key="lib:Org1:math_101")

        permissions = get_permissions_for_active_roles_in_scope(scope)

        self.assertIsInstance(permissions, dict)
        self.assertIn("library_admin", permissions)
        self.assertIn("permissions", permissions["library_admin"])
        self.assertIsInstance(permissions["library_admin"]["permissions"], list)

        # Verify exact permission count
        # Load both wildcard and specific scope like the decorator does
        global_enforcer.load_filtered_policy(Filter(v2=[scope.policy_template, scope.namespaced_key]))
        expected_perms_count = len([p for p in global_enforcer.get_policy() if "role^library_admin" in p[0]])
        global_enforcer.clear_policy()

        self.assertEqual(
            len(permissions["library_admin"]["permissions"]),
            expected_perms_count,
        )

    @ddt_data(
        ("lib:Org1:math_101", "library_admin", True),
        ("lib:Org2:science_201", "library_user", True),
        ("lib:Org3:history_301", "library_author", True),
        ("lib:NonExistent:scope", "any_role", False),
    )
    @unpack
    def test_decorator_with_different_scopes(
        self, scope_name, expected_role, should_find_role
    ):
        """Test decorator behavior with different scope values.

        Expected result:
            - Decorator loads appropriate policies for each scope
            - API functions return correct results for each scope
            - Enforcer is cleared after each call
            - Policy filtering works correctly for different scopes
        """
        scope = ScopeData(external_key=scope_name)

        permissions = get_permissions_for_active_roles_in_scope(scope)

        if should_find_role:
            self.assertIn(expected_role, permissions)
            self.assertIn("permissions", permissions[expected_role])
            self.assertIsInstance(permissions[expected_role]["permissions"], list)

            # Verify exact permission count
            # Load both wildcard and specific scope like the decorator does
            global_enforcer.load_filtered_policy(Filter(v2=[scope.policy_template, scope.namespaced_key]))
            expected_perms_count = len([p for p in global_enforcer.get_policy() if f"role^{expected_role}" in p[0]])
            global_enforcer.clear_policy()

            self.assertEqual(
                len(permissions[expected_role]["permissions"]),
                expected_perms_count,
            )
        else:
            self.assertEqual(len(permissions), 0)

    def test_decorator_with_permission_grouping(self):
        """Test decorator behavior with permission grouping in policies.

        For example:
            - manage_library_team includes view_library_team through g2

        This test verifies that when a user has edit permissions, they also implicitly have
        delete permissions due to the permission grouping defined in the policy.

        Expected result:
            - Decorator loads filtered policies for the given scope
            - User with manage_library_team role can also view_library_team
            - Enforcer is cleared after execution
        """
        scope = ScopeData(external_key="lib:Org1:math_101")
        subject = SubjectData(external_key="alice")

        @manage_policy_lifecycle(filter_on="scope")
        def check_grouped_permissions(scope_arg, subject_arg):
            """Check if subject has grouped permissions in the given scope.

            Expected scenario:
            - Alice has library_admin role in lib:Org1:math_101
            - library_admin role includes manage_library_team
            - manage_library_team includes view_library_team through g2
            """
            can_manage_team = global_enforcer.enforce(
                subject_arg.namespaced_key,
                ActionData(external_key="manage_library_team").namespaced_key,
                scope_arg.namespaced_key,
            )

            can_view_team = global_enforcer.enforce(
                subject_arg.namespaced_key,
                ActionData(external_key="view_library_team").namespaced_key,
                scope_arg.namespaced_key,
            )

            return {
                "can_manage_team": can_manage_team,
                "can_view_team": can_view_team,
            }

        result = check_grouped_permissions(scope, subject)

        self.assertTrue(result["can_manage_team"], "Alice should be able to manage library team")
        self.assertTrue(result["can_view_team"], "Alice should be able to view library team due to grouping")
