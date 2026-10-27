"""Validate parsed schema values against the configured JSON Schema.

The schema owns supported ``schema_version`` values, required fields,
identifier and permission-reference formats, scope formats, collection shapes,
value types, and Paragon icon-name format. Semantic relationship and icon
membership checks remain in :mod:`.validation`.
"""

from __future__ import annotations

import json
from importlib import resources

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from jsonschema import Draft202012Validator

from openedx_authz.constants.schema import AUTHZ_JSON_SCHEMA_SETTING, DEFAULT_AUTHZ_JSON_SCHEMA
from openedx_authz.engine.schema.issues import IssueLevel, ValidationIssue
from openedx_authz.engine.schema.types import ParsedSchemaDocument


def document_validator(schema_resource: str) -> Draft202012Validator:
    """Load an authorization validator from a package resource."""
    schema_package, separator, schema_filename = schema_resource.partition("/")
    if not separator:
        raise ValueError(f"{AUTHZ_JSON_SCHEMA_SETTING} must be a package-anchored resource path.")
    schema_path = resources.files(schema_package).joinpath(schema_filename)
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def configured_schema_resource() -> str:
    """Return the configured JSON Schema resource, including outside Django."""
    try:
        return getattr(settings, AUTHZ_JSON_SCHEMA_SETTING, DEFAULT_AUTHZ_JSON_SCHEMA)
    except ImproperlyConfigured:
        return DEFAULT_AUTHZ_JSON_SCHEMA


class SchemaSyntaxValidator:
    """Collect JSON Schema findings for parsed documents."""

    def validate(self, documents: list[ParsedSchemaDocument]) -> list[ValidationIssue]:
        """Return every structural error from every parsed document."""
        validator = document_validator(configured_schema_resource())
        issues = []
        for document in documents:
            issues.extend(
                ValidationIssue(
                    IssueLevel.ERROR,
                    f"{error.json_path}: {error.message}",
                    document.source.source_id,
                )
                for error in validator.iter_errors(document.data)
            )
        return issues
