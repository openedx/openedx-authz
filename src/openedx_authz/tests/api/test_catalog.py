"""Test cases for the role and permission catalog API functions."""

from django.test import TestCase
from django.utils import timezone

from openedx_authz.api.catalog import get_category_catalog, get_permission_catalog, get_role_catalog
from openedx_authz.api.data import DefinitionKind
from openedx_authz.models.schema import (
    AuthzPermissionCategory,
    AuthzPermissionDefinition,
    AuthzPermissionDependency,
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
            role_id="editor", display_name="Editor", description="Edits", icon="Edit", scopes=["course-v1", "lib"]
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


class TestPermissionCatalogDependencies(CatalogTestCase):
    """Each permission of the catalog lists its direct and indirect dependencies (ADR 0034, ADR 0036)."""

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.edit_course = AuthzPermissionDefinition.objects.create(
            namespace="courses", name="edit_course", display_name="Edit", scopes=["course-v1"]
        )
        cls.publish_course = AuthzPermissionDefinition.objects.create(
            namespace="courses", name="publish_course", display_name="Publish", scopes=["course-v1"]
        )
        for permission, depends_on in (
            (cls.publish_course, cls.manage_team),
            (cls.publish_course, cls.edit_course),
            (cls.edit_course, cls.view_course),
        ):
            AuthzPermissionDependency.objects.create(permission=permission, depends_on=depends_on)

    def _by_identifier(self, scope_types):
        return {p.identifier: p for p in get_permission_catalog(scope_types)}

    def test_lists_direct_and_all_dependencies_sorted(self):
        """``depends_on`` has the direct dependencies and ``all_depends_on`` adds the indirect ones."""
        permissions = self._by_identifier(["course-v1"])

        publish = permissions["courses.publish_course"]
        assert publish.depends_on == ["common.manage_team", "courses.edit_course"]
        assert publish.all_depends_on == ["common.manage_team", "courses.edit_course", "courses.view_course"]
        assert permissions["courses.edit_course"].depends_on == ["courses.view_course"]
        assert permissions["courses.edit_course"].all_depends_on == ["courses.view_course"]

    def test_permission_without_dependencies_has_empty_lists(self):
        """A permission that depends on nothing gets empty lists."""
        view_course = self._by_identifier(["course-v1"])["courses.view_course"]

        assert view_course.depends_on == []
        assert view_course.all_depends_on == []

    def test_follows_dependencies_outside_the_catalog(self):
        """Indirect dependencies are followed through permissions that are not in the returned catalog."""
        AuthzPermissionDependency.objects.create(permission=self.view_library, depends_on=self.publish_course)

        view_library = self._by_identifier(["lib"])["content_libraries.view_library"]

        assert view_library.depends_on == ["courses.publish_course"]
        assert view_library.all_depends_on == [
            "common.manage_team",
            "courses.edit_course",
            "courses.publish_course",
            "courses.view_course",
        ]

    def test_uses_a_constant_number_of_queries(self):
        """Dependencies are loaded with one query however many there are (ADR 0028)."""
        with self.assertNumQueries(3):
            get_permission_catalog(["course-v1"])

        AuthzPermissionDependency.objects.create(permission=self.view_library, depends_on=self.manage_team)
        AuthzPermissionDependency.objects.create(permission=self.manage_team, depends_on=self.view_course)

        with self.assertNumQueries(3):
            get_permission_catalog(["course-v1", "lib"])


class TestHiddenPermissionsAndCategories(CatalogTestCase):
    """Hidden permissions and categories are left out of the catalog."""

    def test_hidden_permission_is_excluded(self):
        """A hidden permission is not in the permission catalog or in role details."""
        AuthzPermissionDefinition.objects.filter(pk=self.view_course.pk).update(hidden=True)

        assert [p.identifier for p in get_permission_catalog(["course-v1"])] == ["common.manage_team"]
        (role,) = get_role_catalog(["course-v1"])
        assert role["permissions"] == ["common.manage_team"]

    def test_hidden_category_hides_its_permissions(self):
        """Permissions of a hidden category are excluded even when they are not hidden themselves."""
        AuthzPermissionCategory.objects.filter(pk=self.team.pk).update(hidden=True)

        permissions = get_permission_catalog(["course-v1", "lib"])

        assert [p.identifier for p in permissions] == ["content_libraries.view_library", "courses.view_course"]
        assert [c.category_id for c in get_category_catalog(permissions)] == ["content"]
        (role,) = get_role_catalog(["course-v1", "lib"])
        assert role["permissions"] == ["content_libraries.view_library", "courses.view_course"]

    def test_category_with_only_hidden_permissions_is_excluded(self):
        """A visible category whose permissions are all hidden is not returned."""
        AuthzPermissionDefinition.objects.filter(pk=self.view_course.pk).update(hidden=True)

        categories = get_category_catalog(get_permission_catalog(["course-v1"]))

        assert [c.category_id for c in categories] == ["team"]

    def test_role_with_only_hidden_permissions_keeps_scope_types(self):
        """A role whose grants are all hidden is listed with no permissions but its scope types."""
        AuthzPermissionDefinition.objects.filter(pk=self.view_course.pk).update(hidden=True)
        only_hidden = AuthzRoleDefinition.objects.create(
            role_id="only_hidden", display_name="Only hidden", scopes=["course-v1"]
        )
        AuthzRolePermission.objects.create(role=only_hidden, permission=self.view_course, scope="course-v1")

        role = next(r for r in get_role_catalog(["course-v1"]) if r["role"] == "only_hidden")

        assert role["permissions"] == []
        assert role["scope_types"] == ["course-v1"]

    def test_hiding_keeps_grants(self):
        """Hiding a permission does not remove its role grants."""
        AuthzPermissionDefinition.objects.filter(pk=self.view_course.pk).update(hidden=True)

        assert AuthzRolePermission.objects.filter(permission=self.view_course).exists()


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
                    "updated_at": None,
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

    def test_custom_role_is_listed_with_its_kind(self):
        """A custom role appears next to the static ones and reports its definition kind."""
        custom = AuthzRoleDefinition.objects.create(
            role_id="custom_designer",
            display_name="Designer",
            scopes=["course-v1"],
            definition_kind=DefinitionKind.USER_DEFINED.value,
        )
        AuthzRolePermission.objects.create(role=custom, permission=self.view_course, scope="course-v1")

        roles = {role["role"]: role for role in get_role_catalog(["course-v1"])}

        self.assertEqual(roles["custom_designer"]["definition_kind"], DefinitionKind.USER_DEFINED.value)
        self.assertEqual(roles["custom_designer"]["permissions"], ["courses.view_course"])
        self.assertEqual(roles["editor"]["definition_kind"], DefinitionKind.STATIC.value)

    def test_removed_custom_role_is_not_listed(self):
        """A removed custom role leaves the catalog even if a grant row were left behind."""
        removed = AuthzRoleDefinition.objects.create(
            role_id="custom_designer",
            display_name="Designer",
            scopes=["course-v1"],
            definition_kind=DefinitionKind.USER_DEFINED.value,
            removed_at=timezone.now(),
        )
        AuthzRolePermission.objects.create(role=removed, permission=self.view_course, scope="course-v1")

        role_ids = [role["role"] for role in get_role_catalog(["course-v1"])]

        self.assertNotIn("custom_designer", role_ids)

    def test_custom_role_without_grants_is_listed_by_its_resource_type(self):
        """A custom role that lost every grant stays listed for its stored resource type only."""
        AuthzRoleDefinition.objects.create(
            role_id="custom_designer",
            display_name="Designer",
            scopes=["course-v1"],
            definition_kind=DefinitionKind.USER_DEFINED.value,
        )

        roles = {role["role"]: role for role in get_role_catalog(["course-v1"])}

        self.assertEqual(roles["custom_designer"]["permissions"], [])
        self.assertEqual(roles["custom_designer"]["scope_types"], ["course-v1"])
        self.assertNotIn("custom_designer", [role["role"] for role in get_role_catalog(["lib"])])

    def test_static_role_without_grants_is_not_listed(self):
        """Only custom roles are listed without grants; a static role still needs one."""
        AuthzRoleDefinition.objects.create(role_id="course_reviewer", display_name="Reviewer", scopes=["course-v1"])

        role_ids = [role["role"] for role in get_role_catalog(["course-v1"])]

        self.assertNotIn("course_reviewer", role_ids)

    def test_uses_a_constant_number_of_queries(self):
        """Listing roles takes three queries however many roles and grants there are (ADR 0028).

        One query matches the custom roles by resource type, one reads the roles and one loads
        their grants with their permissions.
        """
        for index in range(3):
            custom = AuthzRoleDefinition.objects.create(
                role_id=f"custom_designer_{index}",
                display_name=f"Designer {index}",
                scopes=["course-v1"],
                definition_kind=DefinitionKind.USER_DEFINED.value,
            )
            AuthzRolePermission.objects.create(role=custom, permission=self.view_course, scope="course-v1")
        AuthzRoleDefinition.objects.create(
            role_id="custom_empty",
            display_name="Empty",
            scopes=["course-v1"],
            definition_kind=DefinitionKind.USER_DEFINED.value,
        )

        with self.assertNumQueries(3):
            roles = get_role_catalog(["course-v1", "lib"])

        self.assertEqual(len(roles), 5)
