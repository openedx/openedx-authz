"""
Test suite for engine/utils.py policy migration functionality.

This module tests the migration of policies from file-based storage (authz.policy)
to database-backed storage, which is the real-world scenario for the load_policies
management command.
"""

import os

import casbin
from casbin_adapter.models import CasbinRule
from ddt import data, ddt, unpack
from django.db.models import Count
from django.test import TestCase

from openedx_authz import ROOT_DIRECTORY
from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.engine.utils import migrate_policy_between_enforcers
from openedx_authz.tests.test_utils import make_action_key, make_role_key, make_scope_key, make_user_key


@ddt
class TestMigratePolicyBetweenEnforcers(TestCase):
    """
    Test case for migrate_policy_between_enforcers function.

    Tests the migration of policies from the authz.policy file to the database:
    - Loading all policies from file to DB
    - Idempotent migration (running twice doesn't duplicate)
    - Partial migration (some policies already in DB)
    - Preserving existing DB policies not in file
    """

    @classmethod
    def setUpClass(cls):
        """Set up the Casbin model and policy file paths."""
        super().setUpClass()
        engine_config_dir = os.path.join(ROOT_DIRECTORY, "engine", "config")
        cls.model_file = os.path.join(engine_config_dir, "model.conf")
        cls.policy_file = os.path.join(engine_config_dir, "authz.policy")

        if not os.path.isfile(cls.model_file):
            raise FileNotFoundError(f"Model file not found: {cls.model_file}")
        if not os.path.isfile(cls.policy_file):
            raise FileNotFoundError(f"Policy file not found: {cls.policy_file}")

    def setUp(self):
        """Set up fresh enforcers for each test.

        Creates enforcers matching the load_policies command pattern:
        - Source enforcer: file-based (loads from authz.policy file, read-only)
        - Target enforcer: database-backed (global_enforcer, will be cleared)
        """
        # Source enforcer loads policies from the authz.policy file
        self.source_enforcer = casbin.Enforcer(self.model_file, self.policy_file)

        # Target enforcer is the database-backed global enforcer
        self.target_enforcer = AuthzEnforcer.get_enforcer()

        # Clear the target enforcer's database to start fresh
        # This simulates a clean database state before migration
        self._clear_target_enforcer()

    def _clear_target_enforcer(self):
        """Clear all policies from the target (database) enforcer."""
        # Clear the database directly to ensure a clean state
        CasbinRule.objects.all().delete()

        # Reload the enforcer to sync with the now-empty database
        self.target_enforcer.load_policy()

    def test_migrate_all_file_policies_to_database(self):
        """Test migration of all policies from authz.policy file to database.

        Expected Result:
            - All policies from the file are loaded into the database
            - The file contains 25 regular policies (p rules)
            - Policy content matches expected file content
        """
        expected_policy_count = 25

        migrate_policy_between_enforcers(self.source_enforcer, self.target_enforcer)
        self.target_enforcer.load_policy()

        target_policies = self.target_enforcer.get_policy()
        self.assertEqual(
            len(target_policies),
            expected_policy_count,
            f"Expected {expected_policy_count} policies from file, got {len(target_policies)}",
        )

        self.assertIn(
            [
                make_role_key("library_admin"),
                make_action_key("delete_library"),
                make_scope_key("lib", "*"),
                "allow",
            ],
            target_policies,
        )
        self.assertIn(
            [
                make_role_key("library_user"),
                make_action_key("view_library"),
                make_scope_key("lib", "*"),
                "allow",
            ],
            target_policies,
        )

    def test_migrate_no_grouping_policies_from_file(self):
        """Test that no grouping policies (g rules) exist in the authz.policy file.

        Expected Result:
            - The authz.policy file contains no g rules (role assignments)
            - These are expected to come from the database, not the file
            - Migration should result in 0 grouping policies
        """
        migrate_policy_between_enforcers(self.source_enforcer, self.target_enforcer)
        self.target_enforcer.load_policy()

        target_grouping = self.target_enforcer.get_grouping_policy()
        # The file contains no g rules - those come from database/runtime assignment
        self.assertEqual(
            len(target_grouping),
            0,
            "authz.policy file should not contain user role assignments (g rules)",
        )

    def test_migrate_action_inheritance_from_file(self):
        """Test migration of g2 policies (action inheritance) from authz.policy file.

        Expected Result:
            - All g2 rules from the file are migrated to database
            - The file contains 13 g2 rules defining action hierarchies
            - Action inheritance relationships are preserved
        """
        expected_g2_count = 13

        migrate_policy_between_enforcers(self.source_enforcer, self.target_enforcer)
        self.target_enforcer.load_policy()

        target_g2 = self.target_enforcer.get_named_grouping_policy("g2")
        self.assertEqual(
            len(target_g2),
            expected_g2_count,
            f"Expected {expected_g2_count} g2 rules from file, got {len(target_g2)}",
        )

        # Verify a sample of expected g2 rules from the file
        self.assertIn(
            [make_action_key("delete_library"), make_action_key("view_library")],
            target_g2,
        )
        self.assertIn(
            [
                make_action_key("manage_library_team"),
                make_action_key("view_library_team"),
            ],
            target_g2,
        )

    def test_migrate_idempotent(self):
        """Test that running migration twice doesn't duplicate policies.

        Expected Result:
            - Running migration twice results in same number of policies
            - No duplicate policies are created in the database
            - Duplicate detection works correctly for file-to-DB migration
        """
        migrate_policy_between_enforcers(self.source_enforcer, self.target_enforcer)
        self.target_enforcer.load_policy()

        first_policy_count = len(self.target_enforcer.get_policy())
        first_g2_count = len(self.target_enforcer.get_named_grouping_policy("g2"))

        migrate_policy_between_enforcers(self.source_enforcer, self.target_enforcer)
        self.target_enforcer.load_policy()

        second_policy_count = len(self.target_enforcer.get_policy())
        second_g2_count = len(self.target_enforcer.get_named_grouping_policy("g2"))

        self.assertEqual(
            first_policy_count,
            second_policy_count,
            "Running migration twice should not duplicate policies",
        )
        self.assertEqual(
            first_g2_count,
            second_g2_count,
            "Running migration twice should not duplicate g2 rules",
        )

        duplicates = (
            CasbinRule.objects.values("v0", "v1", "v2")
            .annotate(total=Count("*"))
            .filter(total__gt=1)
        )
        duplicate_list = list(duplicates)
        self.assertEqual(
            len(duplicate_list),
            0,
            f"Found {len(duplicate_list)} duplicate policies in database: {duplicate_list}",
        )

    def test_migrate_complete_file_contents(self):
        """Test that all policy types from the file are migrated correctly.

        Expected Result:
            - All regular policies (p) are migrated (25 rules)
            - No role assignments (g) - these come from database
            - All action inheritance rules (g2) are migrated (13 rules)
        """
        migrate_policy_between_enforcers(self.source_enforcer, self.target_enforcer)

        self.assertEqual(
            len(self.target_enforcer.get_policy()),
            25,
            "Should have 25 regular policies from file",
        )
        self.assertEqual(
            len(self.target_enforcer.get_grouping_policy()),
            0,
            "Should have 0 g rules (not stored in file)",
        )
        self.assertEqual(
            len(self.target_enforcer.get_named_grouping_policy("g2")),
            13,
            "Should have 13 g2 rules from file",
        )

    def test_migrate_partial_duplicates(self):
        """Test migration when database already has some policies from the file.

        Expected Result:
            - Only new policies from file are added to database
            - Existing policies are not duplicated
            - Mixed state is handled correctly
        """
        self.target_enforcer.add_policy(
            make_role_key("library_admin"),
            make_action_key("delete_library"),
            make_scope_key("lib", "*"),
            "allow",
        )

        migrate_policy_between_enforcers(self.source_enforcer, self.target_enforcer)

        target_policies = self.target_enforcer.get_policy()
        self.assertEqual(
            len(target_policies),
            25,
            "Should have 25 policies total, with no duplicates",
        )

        duplicates = (
            CasbinRule.objects.values("v0", "v1", "v2")
            .annotate(total=Count("*"))
            .filter(total__gt=1)
        )
        duplicate_list = list(duplicates)
        self.assertEqual(
            len(duplicate_list),
            0,
            f"Found {len(duplicate_list)} duplicate policies in database: {duplicate_list}",
        )

    @data(
        (
            make_role_key("library_admin"),
            make_action_key("delete_library"),
            make_scope_key("lib", "*"),
        ),
        (
            make_role_key("library_user"),
            make_action_key("view_library"),
            make_scope_key("lib", "*"),
        ),
        (
            make_role_key("library_author"),
            make_action_key("edit_library"),
            make_scope_key("lib", "*"),
        ),
    )
    @unpack
    def test_migrate_specific_file_policies(self, role, action, scope):
        """Test that specific policies from the file are migrated correctly.

        Expected Result:
            - Specific policies from authz.policy file are present in database
            - Policy format and content are preserved
        """
        migrate_policy_between_enforcers(self.source_enforcer, self.target_enforcer)

        target_policies = self.target_enforcer.get_policy()
        self.assertIn(
            [role, action, scope, "allow"],
            target_policies,
            f"Policy {role}, {action}, {scope} should be in database",
        )

    @data(
        (make_action_key("delete_library"), make_action_key("view_library")),
        (make_action_key("edit_library"), make_action_key("view_library")),
        (make_action_key("manage_library_team"), make_action_key("view_library_team")),
    )
    @unpack
    def test_migrate_specific_action_inheritance(self, parent_action, child_action):
        """Test that specific action inheritance rules from file are migrated correctly.

        Expected Result:
            - Specific g2 rules from authz.policy file are present in database
            - Action inheritance relationships are preserved
        """
        migrate_policy_between_enforcers(self.source_enforcer, self.target_enforcer)

        target_g2 = self.target_enforcer.get_named_grouping_policy("g2")
        self.assertIn(
            [parent_action, child_action],
            target_g2,
            f"Action inheritance {parent_action} -> {child_action} should be in database",
        )

    def test_migrate_preserves_existing_db_policies(self):
        """Test that migration preserves existing database policies not in the file.

        Expected Result:
            - Existing database policies that aren't in the file remain intact
            - File policies are added to the database
            - No policies are removed
        """
        custom_policy = [
            make_role_key("custom_admin"),
            make_action_key("custom_action"),
            make_scope_key("org", "custom"),
            "allow",
        ]
        self.target_enforcer.add_policy(*custom_policy)

        migrate_policy_between_enforcers(self.source_enforcer, self.target_enforcer)

        target_policies = self.target_enforcer.get_policy()
        self.assertEqual(
            len(target_policies), 26, "Should have 25 file policies + 1 custom policy"
        )
        self.assertIn(
            custom_policy, target_policies, "Custom database policy should be preserved"
        )

    def test_migrate_preserves_user_role_assignments_in_db(self):
        """Test that migration preserves user role assignments (g rules) in the database.

        Expected Result:
            - User role assignments in database are preserved
            - File policies (p and g2) are added
            - No user assignments are removed
        """
        self.target_enforcer.add_grouping_policy(
            make_user_key("user-1"),
            make_role_key("library_admin"),
            make_scope_key("lib", "demo"),
        )
        self.target_enforcer.add_grouping_policy(
            make_user_key("user-2"),
            make_role_key("library_user"),
            make_scope_key("lib", "*"),
        )

        migrate_policy_between_enforcers(self.source_enforcer, self.target_enforcer)

        target_grouping = self.target_enforcer.get_grouping_policy()
        self.assertEqual(
            len(target_grouping), 2, "User role assignments should be preserved"
        )
        self.assertIn(
            [
                make_user_key("user-1"),
                make_role_key("library_admin"),
                make_scope_key("lib", "demo"),
            ],
            target_grouping,
        )

        target_policies = self.target_enforcer.get_policy()
        self.assertEqual(
            len(target_policies), 25, "All 25 policies from file should be loaded"
        )
