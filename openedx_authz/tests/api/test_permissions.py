"""Test cases for permissions API functions.

This test suite verifies the functionality of the permissions API,
including permission retrieval and authorization checks for subjects
within specific scopes.
"""

import casbin
from ddt import data as ddt_data
from ddt import ddt, unpack
from django.test import TestCase

from openedx_authz.api.data import ActionData, RoleData, ScopeData, SubjectData
from openedx_authz.api.permissions import is_subject_allowed
from openedx_authz.api.roles import assign_role_to_subject_in_scope
from openedx_authz.engine.enforcer import enforcer as global_enforcer
from openedx_authz.engine.utils import migrate_policy_between_enforcers


@ddt
class TestPermissionsAPI(TestCase):
    """Test cases for permissions API functions.

    The enforcer used in these test cases is the default global enforcer
    instance from `openedx_authz.engine.enforcer` to ensure consistency
    with production environments.

    These tests verify that the is_subject_allowed function correctly
    checks permissions for subjects in various scopes.
    """

    @classmethod
    def _seed_database_with_policies(cls):
        """Seed the database with policies from the policy file."""
        migrate_policy_between_enforcers(
            source_enforcer=casbin.Enforcer(
                "openedx_authz/engine/config/model.conf",
                "openedx_authz/engine/config/authz.policy",
            ),
            target_enforcer=global_enforcer,
        )

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
            {
                "subject_name": "dave",
                "role_name": "library_collaborator",
                "scope_name": "lib:Org4:english_401",
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

    @ddt_data(
        # Library admin permissions - should allow admin actions
        (
            "alice",
            "delete_library",
            "lib:Org1:math_101",
            True,
        ),
        (
            "alice",
            "publish_library",
            "lib:Org1:math_101",
            True,
        ),
        (
            "alice",
            "manage_library_team",
            "lib:Org1:math_101",
            True,
        ),
        (
            "alice",
            "manage_library_tags",
            "lib:Org1:math_101",
            True,
        ),
        (
            "alice",
            "create_library",
            "lib:Org1:math_101",
            True,
        ),
        # Library user permissions - should allow view actions only
        (
            "bob",
            "view_library",
            "lib:Org2:science_201",
            True,
        ),
        (
            "bob",
            "view_library_team",
            "lib:Org2:science_201",
            True,
        ),
        (
            "bob",
            "reuse_library_content",
            "lib:Org2:science_201",
            True,
        ),
        # Library user should NOT be able to delete
        (
            "bob",
            "delete_library",
            "lib:Org2:science_201",
            False,
        ),
        (
            "bob",
            "publish_library",
            "lib:Org2:science_201",
            False,
        ),
        # Library author permissions
        (
            "carol",
            "edit_library",
            "lib:Org3:history_301",
            True,
        ),
        (
            "carol",
            "delete_library_content",
            "lib:Org3:history_301",
            True,
        ),
        (
            "carol",
            "publish_library_content",
            "lib:Org3:history_301",
            True,
        ),
        (
            "carol",
            "manage_library_tags",
            "lib:Org3:history_301",
            True,
        ),
        # Library author should NOT be able to delete library itself
        (
            "carol",
            "delete_library",
            "lib:Org3:history_301",
            False,
        ),
        # Library collaborator permissions
        (
            "dave",
            "edit_library",
            "lib:Org4:english_401",
            True,
        ),
        (
            "dave",
            "delete_library_content",
            "lib:Org4:english_401",
            True,
        ),
        (
            "dave",
            "manage_library_tags",
            "lib:Org4:english_401",
            True,
        ),
        # Library collaborator should NOT be able to publish library
        (
            "dave",
            "publish_library",
            "lib:Org4:english_401",
            False,
        ),
        # Non-existent user should have no permissions
        (
            "nonexistent_user",
            "view_library",
            "lib:Org1:math_101",
            False,
        ),
        # User in wrong scope should have no permissions
        (
            "alice",
            "delete_library",
            "lib:Org2:science_201",
            False,
        ),
        # Non-existent action should always be denied
        (
            "alice",
            "nonexistent_action",
            "lib:Org1:math_101",
            False,
        ),
    )
    @unpack
    def test_is_subject_allowed(
        self, subject_name, action_name, scope_name, expected_allowed
    ):
        """Test checking if a subject is allowed to perform an action in a scope.

        Expected result:
            - Subject with appropriate role can perform allowed actions
            - Subject cannot perform actions not granted by their role
            - Subject cannot perform actions in scopes where they have no role
            - Non-existent subjects are denied all actions
            - Non-existent actions are always denied
        """
        subject = SubjectData(external_key=subject_name)
        action = ActionData(external_key=action_name)
        scope = ScopeData(external_key=scope_name)

        result = is_subject_allowed(subject, action, scope)

        self.assertEqual(
            result,
            expected_allowed,
            f"Expected {subject_name} to be {'allowed' if expected_allowed else 'denied'} "
            f"for action {action_name} in scope {scope_name}",
        )

    def test_is_subject_allowed_with_multiple_roles_in_different_scopes(self):
        """Test subject with multiple roles in different scopes.

        Expected result:
            - Subject can perform actions in scopes where they have appropriate roles
            - Subject permissions are isolated to their assigned scopes
        """
        # Assign multiple roles to same subject in different scopes
        eve = SubjectData(external_key="eve")

        assign_role_to_subject_in_scope(
            subject=eve,
            role=RoleData(external_key="library_admin"),
            scope=ScopeData(external_key="lib:Org5:project_alpha"),
        )

        assign_role_to_subject_in_scope(
            subject=eve,
            role=RoleData(external_key="library_user"),
            scope=ScopeData(external_key="lib:Org5:project_beta"),
        )

        # Should have admin permissions in project_alpha
        self.assertTrue(
            is_subject_allowed(
                eve,
                ActionData(external_key="delete_library"),
                ScopeData(external_key="lib:Org5:project_alpha"),
            )
        )

        # Should NOT have admin permissions in project_beta (only user role)
        self.assertFalse(
            is_subject_allowed(
                eve,
                ActionData(external_key="delete_library"),
                ScopeData(external_key="lib:Org5:project_beta"),
            )
        )

        # Should have view permissions in project_beta
        self.assertTrue(
            is_subject_allowed(
                eve,
                ActionData(external_key="view_library"),
                ScopeData(external_key="lib:Org5:project_beta"),
            )
        )

    def test_is_subject_allowed_enforcer_cleared_after_execution(self):
        """Test that enforcer is cleared after is_subject_allowed execution.

        Expected result:
            - Function loads policies during execution
            - Function returns correct result
            - Enforcer is cleared after execution (due to decorator)
        """
        subject = SubjectData(external_key="alice")
        action = ActionData(external_key="delete_library")
        scope = ScopeData(external_key="lib:Org1:math_101")

        result = is_subject_allowed(subject, action, scope)

        self.assertTrue(result, "Alice should be allowed to delete library")

    def test_is_subject_allowed_with_case_sensitivity(self):
        """Test that permission checks are case-sensitive.

        Expected result:
            - Actions with different casing are treated as different actions
            - Subject identifiers are case-sensitive
        """
        subject = SubjectData(external_key="alice")
        action_lowercase = ActionData(external_key="delete_library")
        action_uppercase = ActionData(external_key="DELETE_LIBRARY")
        scope = ScopeData(external_key="lib:Org1:math_101")

        self.assertTrue(is_subject_allowed(subject, action_lowercase, scope))
        self.assertFalse(is_subject_allowed(subject, action_uppercase, scope))

    @ddt_data(
        # Test various library scope formats
        ("alice", "delete_library", "lib:Org1:math_101", True),
        # Different subject in different org
        ("bob", "view_library", "lib:Org2:science_201", True),
        # Cross-org access should fail
        ("alice", "delete_library", "lib:Org2:science_201", False),
    )
    @unpack
    def test_is_subject_allowed_with_different_scope_formats(
        self, subject_name, action_name, scope_name, expected_allowed
    ):
        """Test permission checks with different scope naming formats.

        Expected result:
            - Scope format is correctly parsed and used for permission checks
            - Permissions are properly scoped to the correct resource
        """
        subject = SubjectData(external_key=subject_name)
        action = ActionData(external_key=action_name)
        scope = ScopeData(external_key=scope_name)

        result = is_subject_allowed(subject, action, scope)

        self.assertEqual(result, expected_allowed)
