"""Tests for the published authorization JSON Schema."""

import json
from importlib.resources import files

import pytest
from jsonschema import Draft202012Validator, ValidationError


def load_schema(filename: str) -> dict:
    """Load one packaged JSON Schema file."""
    schema_path = files("openedx_authz.engine.schema").joinpath(filename)
    return json.loads(schema_path.read_text(encoding="utf-8"))


@pytest.fixture(name="schema_validator", scope="module")
def fixture_schema_validator():
    """Build a validator from the packaged version 1 schema."""
    return Draft202012Validator(load_schema("authz-schema-v1.json"))


class TestSchemaVersionFiles:
    """Version 1.1 accepts everything 1.0 accepts and adds only ``depends_on`` (ADR 0034 §2)."""

    def test_both_files_are_valid_json_schemas_with_their_own_version(self):
        """Each file is a valid JSON Schema whose ``schema_version`` is a single constant."""
        for filename, version in (("authz-schema-v1.json", "1.0"), ("authz-schema-v1.1.json", "1.1")):
            schema = load_schema(filename)
            Draft202012Validator.check_schema(schema)
            assert schema["properties"]["schema_version"]["const"] == version

    def test_1_1_differs_from_1_0_only_in_version_metadata_and_depends_on(self):
        """The fields both versions share stay identical, so the two files cannot drift apart."""
        v1_0 = load_schema("authz-schema-v1.json")
        v1_1 = load_schema("authz-schema-v1.1.json")

        assert v1_1["$defs"]["permission"]["properties"].pop("depends_on")["$ref"] == "#/$defs/permission_list"
        for schema in (v1_0, v1_1):
            for key in ("$id", "description", "examples"):
                schema.pop(key)
            schema["properties"].pop("schema_version")

        assert v1_1 == v1_0

    def test_1_1_examples_are_valid(self):
        """The examples published in the 1.1 file validate against it."""
        schema = load_schema("authz-schema-v1.1.json")
        validator = Draft202012Validator(schema)

        for example in schema["examples"]:
            validator.validate(example)


class TestPublishedAuthorizationJsonSchema:
    """The published schema enforces the supported permission-list shapes."""

    def test_role_may_declare_an_empty_permission_list(self, schema_validator):
        """A base role may rely entirely on role extensions for its permissions."""
        contribution = {
            "schema_version": "1.0",
            "priority": 100,
            "roles": [
                {
                    "id": "course_staff",
                    "display_name": "Course Staff",
                    "description": "Administers a course.",
                    "scopes": ["course-v1"],
                    "permissions": [],
                }
            ],
        }

        schema_validator.validate(contribution)

    def test_role_extension_permission_edits_remain_non_empty(self, schema_validator):
        """An extension cannot use an empty permission edit to satisfy its change requirement."""
        contribution = {
            "schema_version": "1.0",
            "priority": 100,
            "role_extensions": [{"role_id": "course_staff", "add_permissions": []}],
        }

        with pytest.raises(ValidationError):
            schema_validator.validate(contribution)
