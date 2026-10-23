"""Tests for the published authorization JSON Schema."""

import json
from importlib.resources import files

import pytest
from jsonschema import Draft202012Validator, ValidationError


@pytest.fixture(name="schema_validator", scope="module")
def fixture_schema_validator():
    """Build a validator from the packaged version 1 schema."""
    schema_path = files("openedx_authz.schema").joinpath("authz-schema-v1.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def test_role_may_declare_an_empty_permission_list(schema_validator):
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


def test_role_extension_permission_edits_remain_non_empty(schema_validator):
    """An extension cannot use an empty permission edit to satisfy its change requirement."""
    contribution = {
        "schema_version": "1.0",
        "priority": 100,
        "role_extensions": [{"role_id": "course_staff", "add_permissions": []}],
    }

    with pytest.raises(ValidationError):
        schema_validator.validate(contribution)
