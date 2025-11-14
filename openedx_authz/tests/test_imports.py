"""Test module imports."""
import sys
from unittest import TestCase


class TestImports(TestCase):
    """Test that imports work correctly."""

    def setUp(self):
        """Remove cached modules to ensure fresh imports and detect circular dependencies.
        """
        super().setUp()

        # List of modules to remove from cache to test fresh imports
        modules_to_clear = [
            'openedx_authz.engine.enforcer',
            'openedx_authz.engine.matcher',
            'openedx_authz.engine.adapter',
            'openedx_authz.api',
            'openedx_authz.api.permissions',
            'openedx_authz.api.roles',
            'openedx_authz.api.users',
            'openedx_authz.api.data',
        ]

        for module_name in modules_to_clear:
            if module_name in sys.modules:
                del sys.modules[module_name]

    def test_import_authzenforcer(self):
        """Test that AuthzEnforcer can be imported."""
        from openedx_authz.engine.enforcer import AuthzEnforcer  # pylint: disable=import-outside-toplevel
        try:
            self.assertIsNotNone(AuthzEnforcer)
        except ImportError as e:
            self.fail(f"Failed to import AuthzEnforcer: {e}")
