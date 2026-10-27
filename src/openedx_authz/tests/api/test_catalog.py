"""Test cases for the role and permission catalog API functions."""

from django.test import TestCase

from openedx_authz.api.catalog import get_category_catalog, get_permission_catalog, get_role_catalog
from openedx_authz.api.data import DefinitionKind
from openedx_authz.models.schema import (
    AuthzPermissionCategory,
    AuthzPermissionDefinition,
    AuthzRoleDefinition,
    AuthzRolePermission,
)


class CatalogTestCase(TestCase):
    """Seed a small schema shared by the catalog tests."""

    @classmethod
    def setUpTestData(cls):
        cls.content = AuthzPermissionCategory.objects.create(category_id="content", display_name="Content")
        cls.team = AuthzPermissionCategory.objects.create(category_id="team", display_name="Team")

        cls.view_course = AuthzPermissionDefinition.objects.create(
            namespace="courses", name="view_course", display_name="View", category=cls.content, scopes=["course-v1"]
        )
        cls.view_library = AuthzPermissionDefinition.objects.create(
            namespace="content_libraries", name="view_library", display_name="View", scopes=["lib"]
        )
        cls.manage_team = AuthzPermissionDefinition.objects.create(
            namespace="common",
            name="manage_team",
            display_name="Manage",
            category=cls.team,
            scopes=["course-v1", "lib"],
        )

        cls.editor = AuthzRoleDefinition.objects.create(
            role_id="editor", display_name="Editor", description="Edits", icon="Edit"
        )
        cls.hidden = AuthzRoleDefinition.objects.create(role_id="hidden_role", display_name="Hidden", hidden=True)
        cls.orphan = AuthzRoleDefinition.objects.create(role_id="orphan", display_name="Orphan")
        for role, permission, scope in (
            (cls.editor, cls.view_course, "course-v1"),
            (cls.editor, cls.manage_team, "course-v1"),
            (cls.editor, cls.view_library, "lib"),
            (cls.hidden, cls.view_course, "course-v1"),
        ):
            AuthzRolePermission.objects.create(role=role, permission=permission, scope=scope)


class TestGetPermissionCatalog(CatalogTestCase):
    """Tests for get_permission_catalog."""

    def test_filters_by_scope_type(self):
        """Only permissions supporting a requested scope type are returned, ordered."""
        result = get_permission_catalog(["course-v1"])

        self.assertEqual([p.identifier for p in result], ["common.manage_team", "courses.view_course"])

    def test_several_scope_types_are_a_union(self):
        """A permission matching any requested scope type is included once."""
        result = get_permission_catalog(["course-v1", "lib"])

        self.assertEqual(
            [p.identifier for p in result],
            ["common.manage_team", "content_libraries.view_library", "courses.view_course"],
        )

    def test_unknown_scope_type_returns_nothing(self):
        """No permission supports an unknown scope type."""
        self.assertEqual(get_permission_catalog(["unknown"]), [])

    def test_loads_category_without_extra_queries(self):
        """The category of each permission is loaded with the permissions."""
        result = get_permission_catalog(["course-v1", "lib"])

        with self.assertNumQueries(0):
            categories = [p.category for p in result]

        self.assertEqual(sorted(c.category_id for c in categories if c), ["content", "team"])


class TestGetCategoryCatalog(CatalogTestCase):
    """Tests for get_category_catalog."""

    def test_returns_distinct_categories_ordered(self):
        """Each category is returned once, ordered by category_id."""
        permissions = get_permission_catalog(["course-v1", "lib"])

        self.assertEqual([c.category_id for c in get_category_catalog(permissions)], ["content", "team"])

    def test_ignores_permissions_without_category(self):
        """Permissions without a category contribute nothing."""
        self.assertEqual(get_category_catalog(get_permission_catalog(["lib"])), [self.team])

    def test_empty_permissions(self):
        """No permissions means no categories."""
        self.assertEqual(get_category_catalog([]), [])


class TestGetRoleCatalog(CatalogTestCase):
    """Tests for get_role_catalog."""

    def test_returns_role_with_grants_in_scope_types(self):
        """Only the grants in the requested scope types are listed."""
        self.assertEqual(
            get_role_catalog(["course-v1"]),
            [
                {
                    "role": "editor",
                    "display_name": "Editor",
                    "description": "Edits",
                    "icon": "Edit",
                    "definition_kind": DefinitionKind.STATIC.value,
                    "permissions": ["common.manage_team", "courses.view_course"],
                    "scope_types": ["course-v1"],
                }
            ],
        )

    def test_several_scope_types_merge_grants(self):
        """Grants and scope types are merged across the requested scope types."""
        (role,) = get_role_catalog(["lib", "course-v1"])

        self.assertEqual(
            role["permissions"], ["common.manage_team", "content_libraries.view_library", "courses.view_course"]
        )
        self.assertEqual(role["scope_types"], ["course-v1", "lib"])

    def test_excludes_hidden_roles_and_roles_without_grants(self):
        """Hidden roles and roles with no grants in the scope types are not listed."""
        role_ids = [role["role"] for role in get_role_catalog(["course-v1", "lib"])]

        self.assertEqual(role_ids, ["editor"])

    def test_unknown_scope_type_returns_nothing(self):
        """No role has grants in an unknown scope type."""
        self.assertEqual(get_role_catalog(["unknown"]), [])
