"""
Tests for the Filter class used in selective Casbin policy loading.

This module contains unit tests for the Filter class, which is used to specify
criteria for loading only relevant policy rules from the database instead of
loading all policies. The tests verify proper initialization, attribute handling,
and various filtering scenarios.
"""

import unittest

from openedx_authz.engine.filter import Filter
from openedx_authz.tests.test_utils import make_action_key, make_role_key, make_scope_key, make_user_key


class TestFilter(unittest.TestCase):
    """Tests for Filter class instantiation and default values."""

    def test_default_initialization(self):
        """Test that Filter initializes with empty lists by default."""
        f = Filter()
        self.assertEqual(f.ptype, [])
        self.assertEqual(f.v0, [])
        self.assertEqual(f.v1, [])
        self.assertEqual(f.v2, [])
        self.assertEqual(f.v3, [])
        self.assertEqual(f.v4, [])
        self.assertEqual(f.v5, [])

    def test_initialization_with_ptype(self):
        """Test Filter initialization with ptype parameter."""
        f = Filter(ptype=["p", "g"])
        self.assertEqual(f.ptype, ["p", "g"])
        self.assertEqual(f.v0, [])
        self.assertEqual(f.v1, [])

    def test_initialization_with_multiple_attributes(self):
        """Test Filter initialization with multiple attributes."""
        f = Filter(
            ptype=["p"],
            v0=[make_user_key("alice")],
            v1=[make_action_key("read")],
            v2=[make_scope_key("org", "MIT")]
        )
        self.assertEqual(f.ptype, ["p"])
        self.assertEqual(f.v0, [make_user_key("alice")])
        self.assertEqual(f.v1, [make_action_key("read")])
        self.assertEqual(f.v2, [make_scope_key("org", "MIT")])

    def test_initialization_with_all_attributes(self):
        """Test Filter initialization with all attributes."""
        f = Filter(
            ptype=["p", "g"],
            v0=[make_user_key("alice")],
            v1=[make_action_key("read")],
            v2=[make_scope_key("org", "MIT")],
            v3=["allow"],
            v4=["context1"],
            v5=["context2"],
        )
        self.assertEqual(f.ptype, ["p", "g"])
        self.assertEqual(f.v0, [make_user_key("alice")])
        self.assertEqual(f.v1, [make_action_key("read")])
        self.assertEqual(f.v2, [make_scope_key("org", "MIT")])
        self.assertEqual(f.v3, ["allow"])
        self.assertEqual(f.v4, ["context1"])
        self.assertEqual(f.v5, ["context2"])

    def test_modify_ptype_after_creation(self):
        """Test modifying ptype attribute after Filter creation."""
        f = Filter()
        f.ptype = ["p"]
        self.assertEqual(f.ptype, ["p"])

    def test_modify_multiple_attributes(self):
        """Test modifying multiple attributes after creation."""
        f = Filter()
        f.ptype = ["g"]
        f.v0 = [make_user_key("bob")]
        f.v1 = [make_role_key("admin")]
        self.assertEqual(f.ptype, ["g"])
        self.assertEqual(f.v0, [make_user_key("bob")])
        self.assertEqual(f.v1, [make_role_key("admin")])

    def test_empty_list_assignment(self):
        """Test assigning empty lists to attributes."""
        f = Filter(ptype=["p"])
        f.ptype = []
        self.assertEqual(f.ptype, [])

    def test_none_assignment(self):
        """Test assigning None to attributes."""
        f = Filter()
        f.ptype = None
        self.assertIsNone(f.ptype)

    def test_filter_policy_rules_only(self):
        """Test filter for policy rules (p) only."""
        f = Filter(ptype=["p"])
        self.assertEqual(f.ptype, ["p"])
        self.assertIn("p", f.ptype)

    def test_filter_grouping_rules_only(self):
        """Test filter for grouping rules (g) only."""
        f = Filter(ptype=["g"])
        self.assertEqual(f.ptype, ["g"])
        self.assertIn("g", f.ptype)

    def test_filter_action_grouping_only(self):
        """Test filter for action grouping (g2) only."""
        f = Filter(ptype=["g2"])
        self.assertEqual(f.ptype, ["g2"])
        self.assertIn("g2", f.ptype)

    def test_filter_multiple_policy_types(self):
        """Test filter for multiple policy types."""
        f = Filter(ptype=["p", "g", "g2"])
        self.assertEqual(len(f.ptype), 3)
        self.assertIn("p", f.ptype)
        self.assertIn("g", f.ptype)
        self.assertIn("g2", f.ptype)

    def test_filter_user_permissions(self):
        """Test filter for a specific user's permissions."""
        f = Filter(ptype=["p"], v0=[make_user_key("alice")])
        self.assertEqual(f.ptype, ["p"])
        self.assertEqual(f.v0, [make_user_key("alice")])

    def test_filter_role_assignments(self):
        """Test filter for role assignments for a user."""
        f = Filter(
            ptype=["g"],
            v0=[make_user_key("alice")],
            v1=[make_role_key("admin")],
            v2=[make_scope_key("org", "MIT")]
        )
        self.assertEqual(f.ptype, ["g"])
        self.assertEqual(f.v0, [make_user_key("alice")])
        self.assertEqual(f.v1, [make_role_key("admin")])
        self.assertEqual(f.v2, [make_scope_key("org", "MIT")])

    def test_filter_organization_policies(self):
        """Test filter for all policies related to an organization."""
        f = Filter(v2=[make_scope_key("org", "MIT")])
        self.assertEqual(f.v2, [make_scope_key("org", "MIT")])
        self.assertEqual(f.ptype, [])

    def test_filter_specific_action(self):
        """Test filter for policies with a specific action."""
        f = Filter(ptype=["p"], v1=[make_action_key("edit"), make_action_key("delete")])
        self.assertEqual(f.ptype, ["p"])
        self.assertEqual(f.v1, [make_action_key("edit"), make_action_key("delete")])

    def test_filter_action_hierarchy(self):
        """Test filter for action grouping hierarchy."""
        f = Filter(ptype=["g2"], v0=[make_action_key("manage")])
        self.assertEqual(f.ptype, ["g2"])
        self.assertEqual(f.v0, [make_action_key("manage")])

    def test_filter_deny_policies(self):
        """Test filter for deny effect policies."""
        f = Filter(ptype=["p"], v3=["deny"])
        self.assertEqual(f.ptype, ["p"])
        self.assertEqual(f.v3, ["deny"])

    def test_filter_wildcard_resources(self):
        """Test filter for wildcard resource patterns."""
        f = Filter(ptype=["p"], v2=[make_scope_key("lib", "*"), make_scope_key("course", "*")])
        self.assertEqual(f.ptype, ["p"])
        self.assertIn(make_scope_key("lib", "*"), f.v2)
        self.assertIn(make_scope_key("course", "*"), f.v2)

    def test_complex_permission_filter(self):
        """Test complex filter combining multiple criteria."""
        f = Filter(
            ptype=["p"],
            v0=[make_role_key("instructor"), make_role_key("admin")],
            v1=[make_action_key("edit"), make_action_key("delete")],
            v2=[make_scope_key("course", "CS101"), make_scope_key("course", "CS102")],
        )
        self.assertEqual(len(f.ptype), 1)
        self.assertEqual(len(f.v0), 2)
        self.assertEqual(len(f.v1), 2)
        self.assertEqual(len(f.v2), 2)
