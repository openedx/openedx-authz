"""Tests for migrating explicit Casbin policies between enforcers."""

import os
from tempfile import NamedTemporaryFile

import casbin
from casbin_adapter.models import CasbinRule
from django.db.models import Count
from django.test import TestCase

from openedx_authz import ROOT_DIRECTORY
from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.engine.utils import migrate_policy_between_enforcers
from openedx_authz.tests.test_utils import (
    make_action_key,
    make_role_key,
    make_scope_key,
    make_user_key,
    seed_static_authorization_policies,
)

REMOVED_ACTION_RELATIONSHIPS = (
    ("content_libraries.manage_library_tags", "content_libraries.edit_library_content"),
    ("content_libraries.delete_library", "content_libraries.edit_library_content"),
    ("content_libraries.publish_library_content", "content_libraries.edit_library_content"),
    ("content_libraries.edit_library_content", "content_libraries.view_library"),
    ("content_libraries.reuse_library_content", "content_libraries.view_library"),
    ("content_libraries.publish_library_content", "content_libraries.view_library"),
    ("content_libraries.manage_library_team", "content_libraries.view_library_team"),
    ("content_libraries.delete_library_collection", "content_libraries.edit_library_collection"),
    ("content_libraries.create_library_collection", "content_libraries.edit_library_collection"),
    ("content_libraries.edit_library_collection", "content_libraries.view_library"),
)


class TestMigratePolicyBetweenEnforcers(TestCase):
    """The legacy importer still handles explicit policies and role assignments."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.model_file = os.path.join(ROOT_DIRECTORY, "engine", "config", "model.conf")

    def setUp(self):
        super().setUp()
        policy_file = NamedTemporaryFile(mode="w", suffix=".policy", delete=False)
        policy_file.write("p, role^custom, act^custom.read, lib^*, allow\n")
        policy_file.write("g, user^alice, role^custom, lib^demo\n")
        policy_file.close()
        self.addCleanup(os.unlink, policy_file.name)

        self.source_enforcer = casbin.Enforcer(self.model_file, policy_file.name)
        self.target_enforcer = AuthzEnforcer.get_enforcer()
        CasbinRule.objects.all().delete()
        self.target_enforcer.load_policy()

    def test_migrates_explicit_policy_and_role_assignment(self):
        """The importer copies explicit policies and scoped role assignments."""
        migrate_policy_between_enforcers(self.source_enforcer, self.target_enforcer)

        self.assertEqual(
            self.target_enforcer.get_policy(),
            [["role^custom", "act^custom.read", "lib^*", "allow"]],
        )
        self.assertEqual(
            self.target_enforcer.get_grouping_policy(),
            [["user^alice", "role^custom", "lib^demo"]],
        )

    def test_migration_is_idempotent(self):
        """Importing the same file twice does not create duplicate rows."""
        migrate_policy_between_enforcers(self.source_enforcer, self.target_enforcer)
        migrate_policy_between_enforcers(self.source_enforcer, self.target_enforcer)

        duplicates = CasbinRule.objects.values("ptype", "v0", "v1", "v2", "v3").annotate(
            total=Count("*")
        ).filter(total__gt=1)
        self.assertEqual(list(duplicates), [])

    def test_migration_preserves_existing_policies(self):
        """Importing a file preserves policies already stored in the target."""
        existing_policy = [
            make_role_key("existing"),
            make_action_key("existing.read"),
            make_scope_key("org", "example"),
            "allow",
        ]
        self.target_enforcer.add_policy(*existing_policy)

        migrate_policy_between_enforcers(self.source_enforcer, self.target_enforcer)

        self.assertIn(existing_policy, self.target_enforcer.get_policy())

    def test_migration_preserves_existing_role_assignments(self):
        """Importing a file preserves role assignments already in the target."""
        existing_assignment = [
            make_user_key("bob"),
            make_role_key("existing"),
            make_scope_key("lib", "example"),
        ]
        self.target_enforcer.add_grouping_policy(*existing_assignment)

        migrate_policy_between_enforcers(self.source_enforcer, self.target_enforcer)

        self.assertIn(existing_assignment, self.target_enforcer.get_grouping_policy())

    def test_builtin_roles_explicitly_include_previously_implied_permissions(self):
        """Removing action inheritance does not reduce built-in role permissions."""
        schema_policies = seed_static_authorization_policies(self.target_enforcer)
        permissions_by_role = {}
        for role, action, _scope, _effect in schema_policies:
            permissions_by_role.setdefault(role, set()).add(action)

        for parent, implied in REMOVED_ACTION_RELATIONSHIPS:
            parent_action = make_action_key(parent)
            implied_action = make_action_key(implied)
            roles_with_parent = {
                role for role, actions in permissions_by_role.items() if parent_action in actions
            }
            self.assertTrue(roles_with_parent, f"No built-in role includes {parent_action}")
            self.assertEqual(
                {
                    role
                    for role in roles_with_parent
                    if implied_action not in permissions_by_role[role]
                },
                set(),
                f"Built-in roles with {parent_action} must explicitly include {implied_action}",
            )
