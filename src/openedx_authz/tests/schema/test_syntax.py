"""Tests for structural validation against the configured JSON Schema."""

import json
from unittest.mock import patch

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings

from openedx_authz.constants.schema import DEFAULT_AUTHZ_JSON_SCHEMAS
from openedx_authz.engine.schema.discovery import SchemaDiscovery
from openedx_authz.engine.schema.parsing import SchemaParser
from openedx_authz.engine.schema.syntax import (
    SchemaSyntaxValidator,
    configured_schema_resources,
    document_validator,
)

from .factories import make_parsed_document


def schema_data(block: str, definitions: list[object], *, version: str = "1.0") -> dict:
    """Build raw schema data containing one definition block."""
    return {"schema_version": version, "priority": 100, block: definitions}


def category_data(category_id: str = "cat", *, icon: object | None = None) -> dict:
    """Build parsed data for one permission category."""
    definition = {"id": category_id, "display_name": "Category", "description": "Description."}
    if icon is not None:
        definition["icon"] = icon
    return schema_data("permission_categories", [definition])


def permission_data(
    *, namespace: str = "courses", category_id: str = "cat", scopes=None, version: str = "1.0", depends_on=None
) -> dict:
    """Build parsed data for one permission, with ``depends_on`` only when given."""
    definition = {
        "namespace": namespace,
        "name": "view_course",
        "display_name": "View course",
        "description": "View a course.",
        "category_id": category_id,
        "scopes": ["course-v1"] if scopes is None else scopes,
    }
    if depends_on is not None:
        definition["depends_on"] = depends_on
    return schema_data("permissions", [definition], version=version)


def role_data(*, role_id: str = "course_editor", scopes=None, permissions=None) -> dict:
    """Build parsed data for one role."""
    return schema_data(
        "roles",
        [
            {
                "id": role_id,
                "display_name": "Course editor",
                "description": "Edit a course.",
                "scopes": ["course-v1"] if scopes is None else scopes,
                "permissions": ["courses.view_course"] if permissions is None else permissions,
            }
        ],
    )


def validation_messages(data: object) -> list[str]:
    """Return structural error messages for one parsed value."""
    return [issue.message for issue in SchemaSyntaxValidator().validate([make_parsed_document(data)])]


class TestSchemaSyntaxValidator:
    """JSON Schema owns validation of parsed document structure."""

    def test_uses_built_in_schemas_without_the_setting(self):
        """Without an override, every built-in version is validated by its packaged JSON Schema."""
        assert configured_schema_resources() == DEFAULT_AUTHZ_JSON_SCHEMAS

    @override_settings(OPENEDX_AUTHZ_JSON_SCHEMAS={"1.0": "custom/schema.json"})
    def test_override_replaces_only_the_versions_it_lists(self):
        """Overriding 1.0 does not affect the default 1.1 schema"""
        with patch("openedx_authz.engine.schema.syntax.document_validator") as get_validator:
            get_validator.return_value.iter_errors.return_value = []
            SchemaSyntaxValidator().validate([make_parsed_document({})])

        assert sorted(call.args[0] for call in get_validator.call_args_list) == sorted(
            ["custom/schema.json", DEFAULT_AUTHZ_JSON_SCHEMAS["1.1"]]
        )

    @override_settings(OPENEDX_AUTHZ_JSON_SCHEMAS={})
    def test_empty_override_uses_built_in_schemas(self):
        """An empty mapping overrides nothing."""
        assert configured_schema_resources() == DEFAULT_AUTHZ_JSON_SCHEMAS

    @pytest.mark.parametrize("configured", [DEFAULT_AUTHZ_JSON_SCHEMAS["1.0"], None])
    def test_setting_that_is_not_a_mapping_is_improperly_configured(self, configured):
        """A single resource string, or no value, fails with the expected format."""
        with override_settings(OPENEDX_AUTHZ_JSON_SCHEMAS=configured):
            with pytest.raises(ImproperlyConfigured, match="must map schema_version values"):
                SchemaSyntaxValidator().validate([make_parsed_document(permission_data())])

    @override_settings(OPENEDX_AUTHZ_JSON_SCHEMA=DEFAULT_AUTHZ_JSON_SCHEMAS["1.0"])
    def test_old_setting_name_raises_a_rename_error(self):
        """Setting ``OPENEDX_AUTHZ_JSON_SCHEMA`` raises ``ImproperlyConfigured`` that names the new setting."""
        with pytest.raises(
            ImproperlyConfigured, match="OPENEDX_AUTHZ_JSON_SCHEMA was replaced by OPENEDX_AUTHZ_JSON_SCHEMAS"
        ):
            configured_schema_resources()

    @pytest.mark.parametrize("version", ["2.0", "latest"])
    def test_override_of_a_version_that_is_not_built_in_is_improperly_configured(self, version):
        """The setting can replace built-in versions but cannot add new ones."""
        with override_settings(OPENEDX_AUTHZ_JSON_SCHEMAS={version: DEFAULT_AUTHZ_JSON_SCHEMAS["1.0"]}):
            with pytest.raises(ImproperlyConfigured, match=f"can only override built-in schema versions .*{version}"):
                configured_schema_resources()

    @pytest.mark.parametrize("resource", [None, "", "no-package-anchor.json", 1])
    def test_override_that_is_not_a_package_anchored_resource_is_improperly_configured(self, resource):
        """Each override must be a ``package/file`` resource path."""
        with override_settings(OPENEDX_AUTHZ_JSON_SCHEMAS={"1.1": resource}):
            with pytest.raises(ImproperlyConfigured, match=r"OPENEDX_AUTHZ_JSON_SCHEMAS\['1.1'\] must be"):
                configured_schema_resources()

    def test_each_document_is_validated_against_the_schema_of_its_version(self):
        """A ``1.0`` and a ``1.1`` document are validated together, each by its own JSON Schema."""
        documents = [
            make_parsed_document(permission_data(version="1.0"), "v1_0"),
            make_parsed_document(permission_data(version="1.1", depends_on=["courses.view_course_team"]), "v1_1"),
        ]

        assert not SchemaSyntaxValidator().validate(documents)

    def test_depends_on_is_rejected_in_a_1_0_document(self):
        """``depends_on`` is a 1.1 field, so a 1.0 document that declares it is rejected (ADR 0034 §2)."""
        messages = validation_messages(permission_data(version="1.0", depends_on=["courses.view_course_team"]))

        assert any("depends_on" in message for message in messages)

    def test_1_1_document_without_depends_on_is_valid(self):
        """``depends_on`` stays optional in 1.1."""
        assert not validation_messages(permission_data(version="1.1"))

    @pytest.mark.parametrize(
        "depends_on",
        [
            [],
            ["courses"],
            ["act^courses.view_course"],
            ["courses.view_course_team", "courses.view_course_team"],
            "courses.view_course_team",
        ],
    )
    def test_depends_on_must_be_a_non_empty_list_of_unique_permission_ids(self, depends_on):
        """``depends_on`` reuses the permission list shape: non-empty, unique, complete permission IDs."""
        assert validation_messages(permission_data(version="1.1", depends_on=depends_on))

    def test_role_extension_cannot_declare_depends_on(self):
        """Only the file that defines a permission declares its dependencies (ADR 0034 §1)."""
        data = {
            "schema_version": "1.1",
            "priority": 100,
            "role_extensions": [
                {
                    "role_id": "course_editor",
                    "add_permissions": ["courses.view_course"],
                    "depends_on": ["courses.view_course_team"],
                }
            ],
        }

        assert any("depends_on" in message for message in validation_messages(data))

    @pytest.mark.parametrize("version", ["9.9", "1", 1.1])
    def test_unsupported_schema_version_names_the_supported_versions(self, version):
        """A version without a configured JSON Schema is reported once, listing the supported versions."""
        messages = validation_messages({"schema_version": version, "priority": 100, "unexpected": True})

        assert len(messages) == 1
        assert "'1.0', '1.1'" in messages[0]

    def test_non_string_schema_version_suggests_quoting(self):
        """An unquoted YAML version is parsed as a number, so the error explains how to fix it."""
        messages = validation_messages({"schema_version": 1.0, "priority": 100, "roles": []})

        assert any("Quote the value" in message for message in messages)

    def test_schema_resource_is_loaded_for_each_validator_request(self):
        """Schema loading has no process-global cache or configuration state."""
        with patch("openedx_authz.engine.schema.syntax.resources.files") as schema_file:
            schema_file.return_value.joinpath.return_value.read_text.return_value = json.dumps(
                {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"}
            )

            document_validator("uncached_package/schema.json")
            document_validator("uncached_package/schema.json")

            assert schema_file.call_count == 2

    @pytest.mark.parametrize("data", [None, "value", ["value"]])
    def test_rejects_non_mapping_roots(self, data):
        """Empty, scalar, and list roots are reported as structural errors."""
        assert SchemaSyntaxValidator().validate([make_parsed_document(data)])

    def test_collects_errors_from_every_document_with_source_attribution(self):
        """One pass returns findings from every invalid parsed document."""
        documents = [
            make_parsed_document({"schema_version": "1.0"}, "first"),
            make_parsed_document({"schema_version": "1.0", "unexpected": True}, "second"),
        ]

        issues = SchemaSyntaxValidator().validate(documents)

        assert {issue.source_id for issue in issues} == {document.source.source_id for document in documents}
        assert all(issue.message.startswith("$") for issue in issues)

    def test_unsupported_schema_version_is_error(self):
        """A ``schema_version`` the validator cannot read is rejected."""
        messages = validation_messages({"schema_version": "9.9", "priority": 100, "roles": []})

        assert any("schema_version" in message and "1.0" in message for message in messages)

    def test_non_snakecase_identifier_is_error(self):
        """Identifiers must be lowercase snake_case."""
        assert validation_messages(permission_data(namespace="Courses"))

    def test_casbin_internal_form_rejected(self):
        """An identifier using an internal Casbin form (``act^``) is rejected."""
        assert validation_messages(category_data("act^category"))

    def test_missing_scope_is_error(self):
        """A permission must declare at least one scope."""
        messages = validation_messages(permission_data(scopes=[]))

        assert any("non-empty" in message for message in messages)

    @pytest.mark.parametrize(
        "permission_id", ["courses", "courses.view.course", "courses.", ".view", "courses..view", ""]
    )
    def test_permission_id_must_be_namespace_dot_name(self, permission_id):
        """A permission id must be exactly two identifiers joined by one period."""
        assert validation_messages(role_data(permissions=[permission_id]))

    def test_permission_id_halves_are_validated(self):
        """Both halves of a permission id must be lowercase snake_case."""
        assert validation_messages(role_data(permissions=["Courses.View_Course"]))

    @pytest.mark.parametrize("prefix", ["act^", "role^", "sub^", "scope^", "g^", "p^"])
    def test_every_casbin_prefix_is_rejected(self, prefix):
        """Every reserved Casbin prefix (act^, role^, ...) is rejected in an id."""
        assert validation_messages(role_data(role_id=f"{prefix}thing"))

    @pytest.mark.parametrize("scope", ["Course-V1", "1course", "course v1", "course.v1"])
    def test_invalid_scope_namespace_is_error(self, scope):
        """A malformed scope namespace (caps, leading digit, spaces, dots) is rejected."""
        assert validation_messages(permission_data(scopes=[scope]))

    def test_hyphenated_scope_is_allowed(self):
        """Scope namespaces keep their registered spelling, e.g. ``course-v1``."""
        assert not validation_messages(permission_data(scopes=["course-v1"]))

    def test_role_without_scopes_is_error(self):
        """A role must declare at least one scope."""
        assert validation_messages(role_data(scopes=[]))

    def test_empty_category_id_is_error(self):
        """A category with an empty id is a missing-required-field error."""
        assert validation_messages(category_data(""))

    def test_permission_without_a_category_is_error(self):
        """A permission missing its required category is an error."""
        assert validation_messages(permission_data(category_id=""))

    @pytest.mark.parametrize("icon", ["remove_red_eye", "removeRedEye", "Remove-Red-Eye", "9Mp lowercase"])
    def test_non_pascalcase_icon_is_error(self, icon):
        """An icon name that is not PascalCase is rejected before the export check."""
        assert validation_messages(category_data(icon=icon))

    @pytest.mark.parametrize("builder", [category_data, permission_data])
    def test_hidden_flag_must_be_a_boolean(self, builder):
        """Categories and permissions accept boolean ``hidden`` values only."""
        valid = builder()
        block = next(key for key in valid if key not in ("schema_version", "priority"))

        for value, ok in ((True, True), (False, True), ("yes", False), (1, False)):
            data = {**valid, block: [{**valid[block][0], "hidden": value}]}
            assert (not validation_messages(data)) is ok

    def test_non_string_icon_is_error(self):
        """Icon values must be strings before semantic membership validation."""
        messages = validation_messages(category_data(icon=123))

        assert any("string" in message for message in messages)

    @pytest.mark.parametrize(
        "data",
        [
            {"schema_version": 1.0, "priority": 100},
            {"schema_version": "1.0", "priority": "100"},
            schema_data("permission_categories", [5]),
            schema_data("permission_categories", [{"id": "act^category"}]),
            schema_data("permission_categories", [{"id": ""}]),
            schema_data("permissions", [{"namespace": "Courses"}]),
            schema_data(
                "permissions",
                [
                    {
                        "namespace": "pipeline",
                        "name": "view",
                        "display_name": "View",
                        "description": "View content.",
                        "category_id": "",
                        "scopes": [],
                    }
                ],
            ),
            schema_data("roles", [{"id": "role^editor"}]),
            schema_data(
                "roles",
                [
                    {
                        "id": "editor",
                        "display_name": "Editor",
                        "description": "Edit content.",
                        "scopes": ["Course-V1"],
                        "permissions": ["pipeline"],
                    }
                ],
            ),
            schema_data("permission_categories", [{"id": "cat", "icon": "remove_eye"}]),
            schema_data("permission_categories", [{"id": "cat", "icon": 123}]),
        ],
    )
    def test_schema_preserves_python_structural_checks(self, data):
        """The schema rejects representative types, formats, and required fields."""
        assert SchemaSyntaxValidator().validate([make_parsed_document(data)])

    def test_shipped_documents_match_the_published_schema(self):
        """Every authorization document shipped by this package is structurally valid."""
        resources = SchemaDiscovery().discover()
        documents = SchemaParser().parse(resources)

        assert documents
        assert not SchemaSyntaxValidator().validate(documents)
