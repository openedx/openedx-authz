"""Compatibility tests for definitions contributed by built-in applets."""

from dataclasses import asdict
from pathlib import Path

import yaml

from openedx_authz.constants import permissions, roles
from openedx_authz.data import PermissionData
from openedx_authz.engine.schema.pipeline import SchemaPipeline

COMPILED_SCHEMA_SNAPSHOT = Path(__file__).parents[4] / "docs" / "references" / "compiled-schema.yaml"


def applet_name(source):
    """Return the applet that owns a schema source, or its module when no applet owns it."""
    return source.module.removeprefix("openedx_authz.applets.").removesuffix(".schema")


def snapshot_data(compiled):
    """Return the compiled schema as a readable mapping of roles, permissions, and categories.

    Each role lists its permissions grouped by the applet that adds them, so the snapshot shows
    how base definitions and role extensions compose each role.
    """
    role_definitions = {}
    for role_id, compiled_role in sorted(compiled.roles.items()):
        definition = asdict(compiled_role.definition)
        del definition["id"]
        definition["scopes"] = list(definition["scopes"])
        permissions_by_applet = {}
        for permission in sorted(definition.pop("permissions")):
            for relationship in compiled.role_permission_sources[(role_id, permission)]:
                permissions_by_applet.setdefault(applet_name(relationship.source), []).append(permission)
        definition["permissions"] = dict(sorted(permissions_by_applet.items()))
        role_definitions[role_id] = definition

    permission_definitions = {}
    for permission_id, compiled_permission in sorted(compiled.permissions.items()):
        definition = asdict(compiled_permission.definition)
        definition["scopes"] = list(definition["scopes"])
        permission_definitions[permission_id] = {"applet": applet_name(compiled_permission.sources[0]), **definition}

    category_definitions = {}
    for category_id, compiled_category in sorted(compiled.categories.items()):
        definition = asdict(compiled_category.definition)
        del definition["id"]
        category_definitions[category_id] = {"applet": applet_name(compiled_category.sources[0]), **definition}

    return {"roles": role_definitions, "permissions": permission_definitions, "categories": category_definitions}


class TestBuiltinAppletDefinitions:
    """Built-in applets compose the expected public authorization schema."""

    def test_compiled_schema_matches_expected_definitions(self):
        """The compiled applet schema matches the checked-in snapshot.

        Regenerate the snapshot with ``make compiled_schema`` after changing an applet schema.
        """
        compiled = SchemaPipeline().compile()
        expected = yaml.safe_load(COMPILED_SCHEMA_SNAPSHOT.read_text(encoding="utf-8"))

        assert snapshot_data(compiled) == expected

    def test_compiled_roles_match_public_role_constants(self):
        """Every compiled role has a public constant, and every constant names a compiled role."""
        public_roles = (
            roles.LIBRARY_ADMIN,
            roles.LIBRARY_AUTHOR,
            roles.LIBRARY_CONTRIBUTOR,
            roles.LIBRARY_USER,
            roles.COURSE_ADMIN,
            roles.COURSE_STAFF,
            roles.COURSE_EDITOR,
            roles.COURSE_AUDITOR,
            roles.COURSE_LIMITED_STAFF,
            roles.COURSE_DATA_RESEARCHER,
            roles.COURSE_BETA_TESTER,
        )

        compiled = SchemaPipeline().compile()

        assert set(compiled.roles) == {role.external_key for role in public_roles}

    def test_compiled_permissions_match_public_permission_constants(self):
        """Every compiled permission has a public constant, and every constant names a compiled permission."""
        public_permissions = {
            constant.identifier for constant in vars(permissions).values() if isinstance(constant, PermissionData)
        }

        compiled = SchemaPipeline().compile()

        assert set(compiled.permissions) == public_permissions

    def test_compiled_sources_belong_to_their_owning_applets(self):
        """Compiled definitions expose their owning applet through source metadata."""
        compiled = SchemaPipeline().compile()

        assert compiled.roles["library_admin"].sources[0].module == (
            "openedx_authz.applets.content_libraries.schema"
        )
        assert compiled.roles["course_admin"].sources[0].module == "openedx_authz.applets.course_team_roles.schema"
        assert compiled.permissions["courses.view_course"].sources[0].module == (
            "openedx_authz.applets.course_authoring.schema"
        )
        assert compiled.permissions["courses.view_course_team"].sources[0].module == (
            "openedx_authz.applets.course_authoring.schema"
        )
