"""Utilities for rendering a compiled schema as a readable snapshot."""

from dataclasses import asdict

from openedx_authz.engine.schema.types import (
    CompiledDefinition,
    CompiledSchema,
    RelationshipSource,
    SourceRecord,
)


def source_applet_name(source: SourceRecord) -> str:
    """Return the applet that owns a schema source, or its module when no applet owns it."""
    return source.module.removeprefix("openedx_authz.applets.").removesuffix(".schema")


def group_role_permissions(
    role_id: str,
    permissions: tuple[str, ...],
    relationships: dict[tuple[str, str], list[RelationshipSource]],
) -> dict[str, list[str]]:
    """Group a role's permissions by every applet that contributed each relationship."""
    permissions_by_applet: dict[str, list[str]] = {}
    for permission in sorted(permissions):
        for relationship in relationships[(role_id, permission)]:
            permissions_by_applet.setdefault(source_applet_name(relationship.source), []).append(permission)
    return dict(sorted(permissions_by_applet.items()))


def render_role(
    role_id: str,
    compiled_role: CompiledDefinition,
    relationships: dict[tuple[str, str], list[RelationshipSource]],
) -> dict[str, object]:
    """Render one compiled role for the readable snapshot."""
    definition = asdict(compiled_role.definition)
    del definition["id"]
    definition["scopes"] = list(definition["scopes"])
    permissions = definition.pop("permissions")
    definition["permissions"] = group_role_permissions(role_id, permissions, relationships)
    return definition


def render_permission(compiled_permission: CompiledDefinition) -> dict[str, object]:
    """Render one compiled permission with its owning applet."""
    definition = asdict(compiled_permission.definition)
    definition["scopes"] = list(definition["scopes"])
    return {"applet": source_applet_name(compiled_permission.sources[0]), **definition}


def render_category(compiled_category: CompiledDefinition) -> dict[str, object]:
    """Render one compiled permission category with its owning applet."""
    definition = asdict(compiled_category.definition)
    del definition["id"]
    return {"applet": source_applet_name(compiled_category.sources[0]), **definition}


def snapshot_data(compiled: CompiledSchema) -> dict[str, dict[str, dict[str, object]]]:
    """
    Return the compiled schema as a readable mapping of roles, permissions, and categories.

    Each role lists its permissions grouped by the applet that adds them, so the snapshot shows
    how base definitions and role extensions compose each role.
    """
    role_definitions = {
        role_id: render_role(role_id, compiled_role, compiled.role_permission_sources)
        for role_id, compiled_role in sorted(compiled.roles.items())
    }
    permission_definitions = {
        permission_id: render_permission(compiled_permission)
        for permission_id, compiled_permission in sorted(compiled.permissions.items())
    }
    category_definitions = {
        category_id: render_category(compiled_category)
        for category_id, compiled_category in sorted(compiled.categories.items())
    }

    return {"roles": role_definitions, "permissions": permission_definitions, "categories": category_definitions}
