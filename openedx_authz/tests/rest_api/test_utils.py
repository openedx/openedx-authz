"""Unit tests for openedx_authz.rest_api.utils."""

from django.test import TestCase

from openedx_authz.rest_api.data import AssignmentSortField
from openedx_authz.rest_api.utils import sort_assignments


class TestSortAssignments(TestCase):
    """Tests for sort_assignments."""

    def test_invalid_sort_field_raises_value_error(self):
        """Passing an unrecognised sort_by value raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            sort_assignments(assignments=[], sort_by="invalid_field")

        self.assertIn("invalid_field", str(ctx.exception))
        self.assertIn("Invalid field", str(ctx.exception))

    def test_invalid_sort_order_raises_value_error(self):
        """Passing an unrecognised order value raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            sort_assignments(assignments=[], sort_by=AssignmentSortField.ROLE, order="invalid_order")

        self.assertIn("invalid_order", str(ctx.exception))
        self.assertIn("Invalid order", str(ctx.exception))
