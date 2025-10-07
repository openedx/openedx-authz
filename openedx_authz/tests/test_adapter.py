"""
Tests for the ExtendedAdapter class used in Casbin policy management.

This module contains unit tests for the ExtendedAdapter class, which extends
the base Django adapter with filtering capabilities for efficient policy loading.
The tests verify proper query filtering, ordering, and the adapter's filtering
capability reporting.
"""

from casbin_adapter.models import CasbinRule
from ddt import data as ddt_data
from ddt import ddt, unpack
from django.db.models import QuerySet
from django.test import TestCase

from openedx_authz.engine.adapter import ExtendedAdapter
from openedx_authz.engine.filter import Filter
from openedx_authz.tests.test_utils import make_action_key, make_role_key, make_scope_key, make_user_key


@ddt
class TestExtendedAdapter(TestCase):
    """
    Tests for the ExtendedAdapter class.

    This test class verifies the behavior of the ExtendedAdapter, including:
    - Query filtering with various filter criteria
    - Filter combinations with policy types, roles, and scopes
    - Query result ordering
    - Filtering capability reporting
    """

    def setUp(self):
        """Set up test environment with sample policy data."""
        super().setUp()
        self.adapter = ExtendedAdapter()

        # Create test policy rules
        CasbinRule.objects.create(
            ptype="p",
            v0=make_role_key("library_admin"),
            v1=make_action_key("edit"),
            v2=make_scope_key("lib", "*"),
            v3="allow"
        )
        CasbinRule.objects.create(
            ptype="p",
            v0=make_role_key("library_user"),
            v1=make_action_key("read"),
            v2=make_scope_key("lib", "*"),
            v3="allow"
        )
        CasbinRule.objects.create(
            ptype="g",
            v0=make_user_key("alice"),
            v1=make_role_key("library_admin"),
            v2=make_scope_key("lib", "test-lib")
        )
        CasbinRule.objects.create(
            ptype="g",
            v0=make_user_key("bob"),
            v1=make_role_key("library_user"),
            v2=make_scope_key("lib", "test-lib")
        )

    def test_is_filtered_returns_true(self):
        """Test that adapter correctly reports filtering capability.

        Expected result:
            - The adapter's is_filtered() method returns True
        """
        self.assertTrue(self.adapter.is_filtered())

    def test_filter_query_no_filter(self):
        """Test filtering policies without any filter criteria.

        When no filter criteria are provided, all policy rules should be returned.

        Expected result:
            - All CasbinRule objects are returned
            - Result is a QuerySet instance
        """
        filter_obj = Filter()
        queryset = CasbinRule.objects.all()
        filtered = self.adapter.filter_query(queryset, filter_obj)

        self.assertIsInstance(filtered, QuerySet)
        self.assertEqual(filtered.count(), CasbinRule.objects.count())

    def test_filter_query_with_ptype_filter(self):
        """Test filtering policies by policy type.

        When filtering by ptype='p', only policy rules (not grouping rules)
        should be returned.

        Expected result:
            - Only 'p' type policy rules are returned
            - No grouping rules ('g') are included
        """
        filter_obj = Filter(ptype=["p"])
        queryset = CasbinRule.objects.all()
        filtered = self.adapter.filter_query(queryset, filter_obj)

        self.assertIsInstance(filtered, QuerySet)
        self.assertGreater(filtered.count(), 0)

        for rule in filtered:
            self.assertEqual(rule.ptype, "p")

    def test_filter_query_with_role_filter(self):
        """Test filtering policies by role (v0 attribute).

        When filtering by a specific role, only policies for that role
        should be returned.

        Expected result:
            - Only policies for library_admin role are returned
            - Exactly 1 policy matches the filter
        """
        filter_obj = Filter(ptype=["p"], v0=[make_role_key("library_admin")])
        queryset = CasbinRule.objects.all()
        filtered = self.adapter.filter_query(queryset, filter_obj)

        self.assertIsInstance(filtered, QuerySet)
        self.assertEqual(filtered.count(), 1)

        for rule in filtered:
            self.assertEqual(rule.ptype, "p")
            self.assertEqual(rule.v0, make_role_key("library_admin"))

    def test_filter_query_with_multiple_ptypes(self):
        """Test filtering with multiple policy types.

        When filtering with ptype=['p', 'g'], both policy and grouping
        rules should be returned.

        Expected result:
            - Both 'p' and 'g' type rules are returned
            - All CasbinRule objects match (4 total from setUp)
        """
        filter_obj = Filter(ptype=["p", "g"])
        queryset = CasbinRule.objects.all()
        filtered = self.adapter.filter_query(queryset, filter_obj)

        self.assertIsInstance(filtered, QuerySet)
        self.assertEqual(filtered.count(), CasbinRule.objects.count())

        for rule in filtered:
            self.assertIn(rule.ptype, ["p", "g"])

    def test_filter_query_with_scope_filter(self):
        """Test filtering policies by scope (v2 attribute).

        When filtering by scope, only policies for that scope should be returned.

        Expected result:
            - Only policies with 'lib^*' scope are returned
            - At least one matching policy exists
        """
        filter_obj = Filter(v2=[make_scope_key("lib", "*")])
        queryset = CasbinRule.objects.all()
        filtered = self.adapter.filter_query(queryset, filter_obj)

        self.assertIsInstance(filtered, QuerySet)
        self.assertGreater(filtered.count(), 0)

        for rule in filtered:
            self.assertEqual(rule.v2, make_scope_key("lib", "*"))

    def test_filter_query_ordering(self):
        """Test that filtered queries are ordered by id.

        Results should always be ordered consistently by id for predictable behavior.

        Expected result:
            - Query results are ordered by id in ascending order
            - IDs are sequential and sorted
        """
        filter_obj = Filter()
        queryset = CasbinRule.objects.all()
        filtered = self.adapter.filter_query(queryset, filter_obj)

        ids = list(filtered.values_list('id', flat=True))
        self.assertEqual(ids, sorted(ids))

    @ddt_data(
        (Filter(ptype=["p"]), 2),
        (Filter(ptype=["g"]), 2),
        (Filter(ptype=["p", "g"]), 4),
        (Filter(v0=[make_role_key("library_admin")]), 1),
        (Filter(v0=[make_user_key("alice")]), 1),
        (Filter(v2=[make_scope_key("lib", "*")]), 2),
    )
    @unpack
    def test_filter_query_counts(self, filter_obj, expected_count):
        """
        Test that various filter combinations return expected counts.

        This verifies that different filter criteria produce the expected
        number of matching policy rules.

        Expected result:
            - Each filter produces the expected number of matching CasbinRule objects
            - Filter combinations work correctly
        """
        queryset = CasbinRule.objects.all()
        filtered = self.adapter.filter_query(queryset, filter_obj)

        self.assertEqual(filtered.count(), expected_count)

    def test_filter_query_combined_filters(self):
        """Test filtering with multiple criteria combined.

        When combining ptype and v0 filters, only rules matching both
        criteria should be returned.

        Expected result:
            - Only grouping rules ('g' type) are returned
            - Only rules for alice or bob are included
            - Exactly 2 matching rules exist
        """
        filter_obj = Filter(
            ptype=["g"],
            v0=[make_user_key("alice"), make_user_key("bob")]
        )
        queryset = CasbinRule.objects.all()
        filtered = self.adapter.filter_query(queryset, filter_obj)

        self.assertEqual(filtered.count(), 2)

        for rule in filtered:
            self.assertEqual(rule.ptype, "g")
            self.assertIn(rule.v0, [make_user_key("alice"), make_user_key("bob")])
