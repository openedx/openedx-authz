"""Unit tests for rendering compiled schemas as readable snapshots."""

from dataclasses import replace

from openedx_authz.constants import SchemaOriginKind
from openedx_authz.engine.schema.snapshot import (
    group_role_permissions,
    render_category,
    render_permission,
    render_role,
    snapshot_data,
    source_applet_name,
)
from openedx_authz.engine.schema.types import (
    CompiledDefinition,
    CompiledSchema,
    PermissionCategory,
    PermissionDefinition,
    RelationshipSource,
    RoleDefinition,
)
from openedx_authz.tests.schema.factories import make_source


def schema_source(module):
    """Build a source record for snapshot rendering tests."""
    return replace(make_source(), module=module)


class TestCompiledSchemaSnapshot:
    """Compiled definitions render as deterministic, applet-oriented snapshot data."""

    def test_source_applet_name_normalizes_builtin_applet_modules(self):
        """Built-in schema modules render as applet names while external modules remain unchanged."""
        assert source_applet_name(schema_source("openedx_authz.applets.course_authoring.schema")) == (
            "course_authoring"
        )
        assert source_applet_name(schema_source("example_plugin.authz")) == "example_plugin.authz"

    def test_group_role_permissions_preserves_each_contributing_applet(self):
        """Role permissions are grouped under every applet that contributed the relationship."""
        base_source = schema_source("openedx_authz.applets.course_team_roles.schema")
        extension_source = schema_source("openedx_authz.applets.course_authoring.schema")
        relationships = {
            ("course_editor", "courses.edit_course"): [
                RelationshipSource(extension_source, SchemaOriginKind.EXTENSION, 200)
            ],
            ("course_editor", "courses.view_course"): [
                RelationshipSource(base_source, SchemaOriginKind.BASE, 100),
                RelationshipSource(extension_source, SchemaOriginKind.EXTENSION, 200),
            ],
        }

        assert group_role_permissions(
            "course_editor",
            ("courses.view_course", "courses.edit_course"),
            relationships,
        ) == {
            "course_authoring": ["courses.edit_course", "courses.view_course"],
            "course_team_roles": ["courses.view_course"],
        }

    def test_definition_renderers_shape_each_snapshot_section(self):
        """Role, permission, and category renderers expose the fields expected by the snapshot."""
        source = schema_source("openedx_authz.applets.course_authoring.schema")
        role = CompiledDefinition(
            "course_editor",
            RoleDefinition("course_editor", "Editor", "Edits courses", ("course",), ()),
            (source,),
        )
        permission = CompiledDefinition(
            "courses.edit_course",
            PermissionDefinition(
                "courses", "edit_course", "Edit course", "Edits a course", "course_content", ("course",)
            ),
            (source,),
        )
        category = CompiledDefinition(
            "course_content",
            PermissionCategory("course_content", "Course content", "Course content operations"),
            (source,),
        )

        assert render_role("course_editor", role, {}) == {
            "display_name": "Editor",
            "description": "Edits courses",
            "scopes": ["course"],
            "permissions": {},
            "icon": None,
            "hidden": False,
        }
        assert render_permission(permission) == {
            "applet": "course_authoring",
            "namespace": "courses",
            "name": "edit_course",
            "display_name": "Edit course",
            "description": "Edits a course",
            "category_id": "course_content",
            "scopes": ["course"],
            "icon": None,
        }
        assert render_category(category) == {
            "applet": "course_authoring",
            "display_name": "Course content",
            "description": "Course content operations",
            "icon": None,
        }

    def test_snapshot_data_orders_definition_identifiers(self):
        """Snapshot sections use deterministic identifier ordering."""
        source = schema_source("openedx_authz.applets.course_authoring.schema")
        categories = {
            category_id: CompiledDefinition(
                category_id,
                PermissionCategory(category_id, category_id.title(), "Description"),
                (source,),
            )
            for category_id in ("z_category", "a_category")
        }

        snapshot = snapshot_data(CompiledSchema(categories=categories))

        assert list(snapshot["categories"]) == ["a_category", "z_category"]

    def test_role_permissions_follow_role_metadata(self):
        """Role permissions remain after role metadata in the serialized snapshot."""
        source = schema_source("openedx_authz.applets.course_team_roles.schema")
        role = CompiledDefinition(
            "course_editor",
            RoleDefinition("course_editor", "Editor", "Edits courses", ("course",), ()),
            (source,),
        )

        rendered = render_role("course_editor", role, {})

        assert list(rendered) == ["display_name", "description", "scopes", "icon", "hidden", "permissions"]
