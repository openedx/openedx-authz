"""Tests for the ``openedx_authz.authz`` schema-provider entry point.

These tests pin the contract of the ``authz.schema`` entry point (ADR 0019):
``get_schema_resources`` must return the declared schema *directories*, and each
of those directories must resolve to a real packaged directory containing at
least one ``.yaml`` file, so that discovery via ``importlib.resources`` cannot
fail silently at runtime.
"""

from importlib.resources import files
from unittest import TestCase

from openedx_authz import authz


class TestSchemaProvider(TestCase):
    """Test the ``openedx_authz`` schema-provider entry point."""

    def test_get_schema_resources_returns_declared_directories(self):
        """The entry point returns the declared directories as a fresh list."""
        result = authz.get_schema_resources()

        self.assertEqual(result, list(authz.SCHEMA_DIRECTORIES))
        # Must be a list (a copy), not the underlying tuple, so callers can
        # mutate the result without affecting module state.
        self.assertIsInstance(result, list)
        self.assertIsNot(result, authz.SCHEMA_DIRECTORIES)

    def test_declared_directories_exist_and_contain_yaml(self):
        """Every declared directory resolves to a packaged dir with schema files.

        Guards against a renamed or removed ``authz/schema`` directory turning
        into a silent schema-discovery failure at runtime.
        """
        for directory in authz.get_schema_resources():
            with self.subTest(directory=directory):
                parts = [segment for segment in directory.strip("/").split("/") if segment]
                anchor, subpath = parts[0], "/".join(parts[1:])
                target = files(anchor)
                if subpath:
                    target = target.joinpath(subpath)
                self.assertTrue(target.is_dir(), f"missing schema directory: {directory}")
                yaml_files = [
                    entry.name
                    for entry in target.iterdir()
                    if entry.is_file() and entry.name.endswith((".yaml", ".yml"))
                ]
                self.assertTrue(yaml_files, f"no .yaml files in schema directory: {directory}")
