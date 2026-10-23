"""Test module imports."""

import sys
from importlib import import_module
from unittest import TestCase

from openedx_authz.constants import permissions, roles


class TestImports(TestCase):
    """Test that imports work correctly."""

    def setUp(self):
        """Remove cached modules to ensure fresh imports and detect circular dependencies."""
        super().setUp()

        # List of modules to remove from cache to test fresh imports
        modules_to_clear = [
            "openedx_authz.engine.enforcer",
            "openedx_authz.engine.matcher",
            "openedx_authz.engine.adapter",
            "openedx_authz.api",
            "openedx_authz.api.permissions",
            "openedx_authz.api.roles",
            "openedx_authz.api.users",
            "openedx_authz.api.data",
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

    def test_applet_permission_constants_are_reexported(self):
        """Existing permission imports refer to the objects owned by each applet."""
        applet_constants = {
            "openedx_authz.applets.content_libraries.constants": ("VIEW_LIBRARY",),
            "openedx_authz.applets.course_authoring.constants": (
                "COURSES_VIEW_COURSE",
                "COURSES_VIEW_COURSE_TEAM",
                "COURSES_MANAGE_COURSE_TEAM",
            ),
            "openedx_authz.applets.course_team_roles.constants": (
                "COURSES_LEGACY_INSTRUCTOR_ROLE_PERMISSIONS",
            ),
            "openedx_authz.applets.enrollments.constants": ("COURSES_VIEW_ENROLLMENTS",),
            "openedx_authz.applets.learner_grading.constants": ("COURSES_VIEW_GRADEBOOK",),
            "openedx_authz.applets.learner_administration.constants": ("COURSES_VIEW_COURSE_INFO",),
        }

        for module_name, names in applet_constants.items():
            module = import_module(module_name)
            for name in names:
                with self.subTest(module=module_name, name=name):
                    self.assertIs(getattr(permissions, name), getattr(module, name))

    def test_content_library_roles_are_reexported(self):
        """Existing Library role imports refer to the applet-owned role objects."""
        applet_constants = import_module("openedx_authz.applets.content_libraries.roles")

        for name in ("LIBRARY_ADMIN", "LIBRARY_AUTHOR", "LIBRARY_CONTRIBUTOR", "LIBRARY_USER"):
            with self.subTest(name=name):
                self.assertIs(getattr(roles, name), getattr(applet_constants, name))

    def test_course_team_roles_are_reexported(self):
        """Existing course role imports refer to the applet-owned role objects."""
        applet_roles = import_module("openedx_authz.applets.course_team_roles.roles")

        for name in applet_roles.__all__:
            with self.subTest(name=name):
                self.assertIs(getattr(roles, name), getattr(applet_roles, name))
