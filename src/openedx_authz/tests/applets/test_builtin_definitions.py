"""Compatibility tests for definitions contributed by built-in applets."""

from pathlib import Path

import yaml

from openedx_authz.constants import permissions, roles
from openedx_authz.data import PermissionData
from openedx_authz.engine.schema.pipeline import SchemaPipeline
from openedx_authz.engine.schema.snapshot import snapshot_data

COMPILED_SCHEMA_SNAPSHOT = Path(__file__).parents[4] / "docs" / "references" / "compiled-schema.yaml"


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

    def test_course_editor_and_auditor_remain_visible(self):
        """The applet split preserves the public visibility of the editor and auditor roles."""
        compiled = SchemaPipeline().compile()

        assert compiled.roles["course_editor"].definition.hidden is False
        assert compiled.roles["course_auditor"].definition.hidden is False

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
        assert compiled.permissions["courses.view_enrollments"].sources[0].module == (
            "openedx_authz.applets.enrollments.schema"
        )
        assert compiled.permissions["courses.view_gradebook"].sources[0].module == (
            "openedx_authz.applets.learner_grading.schema"
        )
        assert compiled.permissions["courses.view_cohorts"].sources[0].module == (
            "openedx_authz.applets.learner_administration.schema"
        )
