"""Compatibility tests for definitions contributed by built-in applets."""

import json
from dataclasses import asdict
from pathlib import Path

from openedx_authz.constants import roles
from openedx_authz.engine.schema.pipeline import SchemaPipeline

COMPILED_SCHEMA_FIXTURE = Path(__file__).with_name("fixtures") / "compiled_schema.json"


def _schema_data(compiled):
    """Return the behavior-bearing compiled schema fields in a stable form."""
    role_definitions = {}
    for key, value in sorted(compiled.roles.items()):
        definition = asdict(value.definition)
        definition["permissions"] = sorted(definition["permissions"])
        role_definitions[key] = definition

    data = {
        "categories": {key: asdict(value.definition) for key, value in sorted(compiled.categories.items())},
        "permissions": {key: asdict(value.definition) for key, value in sorted(compiled.permissions.items())},
        "roles": role_definitions,
        "role_permission_pairs": compiled.role_permission_pairs(),
    }
    return json.loads(json.dumps(data))


class TestBuiltinAppletDefinitions:
    """Built-in applets compose the expected public authorization schema."""

    def test_compiled_schema_matches_expected_definitions(self):
        """The compiled applet schema matches the checked-in definition set."""
        compiled = SchemaPipeline().compile()
        expected = json.loads(COMPILED_SCHEMA_FIXTURE.read_text(encoding="utf-8"))

        assert _schema_data(compiled) == expected

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
