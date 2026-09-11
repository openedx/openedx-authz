"""Tests for the ``openedx_authz.authz`` schema-provider entry point.

These tests pin the contract of the ``authz.schema`` entry point (ADR 0019):
``get_schema_resources`` must return the declared schema paths, and each of
those paths must resolve to a real packaged resource so that discovery via
``importlib.resources`` cannot fail silently at runtime.
"""

from importlib.resources import files
from unittest import TestCase

from openedx_authz import authz


class TestSchemaProvider(TestCase):
    """Test the ``openedx_authz`` schema-provider entry point."""

    def test_get_schema_resources_returns_declared_paths(self):
        """The entry point returns the declared resources as a fresh list."""
        result = authz.get_schema_resources()

        self.assertEqual(result, list(authz.SCHEMA_RESOURCES))
        # Must be a list (a copy), not the underlying tuple, so callers can
        # mutate the result without affecting module state.
        self.assertIsInstance(result, list)
        self.assertIsNot(result, authz.SCHEMA_RESOURCES)

    def test_declared_schema_resources_exist_on_disk(self):
        """Every declared resource resolves to a packaged file.

        Guards against a renamed or removed ``.authz.yaml`` file turning into a
        silent schema-discovery failure at runtime.
        """
        package_root = files("openedx_authz.authz")

        for resource in authz.get_schema_resources():
            with self.subTest(resource=resource):
                self.assertTrue(
                    (package_root / resource).is_file(),
                    f"missing schema resource: {resource}",
                )
