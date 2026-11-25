"""Validate parsed schema values against the configured JSON Schemas.

The schemas own supported ``schema_version`` values, required fields,
identifier and permission-reference formats, scope formats, collection shapes,
value types, and Paragon icon-name format. Semantic relationship and icon
membership checks remain in :mod:`.validation`.

Each document is validated against the JSON Schema of the ``schema_version`` it
declares (ADR 0034 §2), so documents of different supported versions can be
validated together.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from importlib import resources
from types import MappingProxyType

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from jsonschema import Draft202012Validator

from openedx_authz.constants.schema import (
    AUTHZ_JSON_SCHEMA_V1_0,
    AUTHZ_JSON_SCHEMAS_SETTING,
    DEFAULT_AUTHZ_JSON_SCHEMAS,
    REMOVED_AUTHZ_JSON_SCHEMA_SETTING,
)
from openedx_authz.engine.schema.issues import IssueLevel, ValidationIssue
from openedx_authz.engine.schema.types import ParsedSchemaDocument


def document_validator(schema_resource: str) -> Draft202012Validator:
    """Load an authorization validator from a package resource."""
    schema_package, separator, schema_filename = schema_resource.partition("/")
    if not separator:
        raise ValueError(f"{AUTHZ_JSON_SCHEMAS_SETTING} values must be package-anchored resource paths.")
    schema_path = resources.files(schema_package).joinpath(schema_filename)
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


_UNSET = object()


def _read_setting(name: str) -> object:
    """Return a Django setting, or ``_UNSET`` when it is absent or settings are not configured."""
    try:
        return getattr(settings, name, _UNSET)
    except ImproperlyConfigured:
        return _UNSET


def configured_schema_resources() -> Mapping[str, str]:
    """Return the JSON Schema resource for each supported ``schema_version``, including outside Django.

    The built-in schemas are the base. ``OPENEDX_AUTHZ_JSON_SCHEMAS`` replaces only the versions it
    lists, so a deployment that overrides one version keeps every other built-in version, including
    versions added by later releases. It can replace built-in versions but not add new ones.

    Raises:
        ImproperlyConfigured: If the removed ``OPENEDX_AUTHZ_JSON_SCHEMA`` setting is set, or if
            ``OPENEDX_AUTHZ_JSON_SCHEMAS`` is not a mapping, names a version that is not built in, or
            maps a version to anything but a package-anchored resource path.
    """
    if _read_setting(REMOVED_AUTHZ_JSON_SCHEMA_SETTING) is not _UNSET:
        raise ImproperlyConfigured(
            f"{REMOVED_AUTHZ_JSON_SCHEMA_SETTING} was replaced by {AUTHZ_JSON_SCHEMAS_SETTING}, which maps "
            f'each schema_version to a JSON Schema resource, for example {{"1.0": "{AUTHZ_JSON_SCHEMA_V1_0}"}}. '
            "List only the versions to override."
        )
    configured = _read_setting(AUTHZ_JSON_SCHEMAS_SETTING)
    if configured is _UNSET:
        return DEFAULT_AUTHZ_JSON_SCHEMAS
    if not isinstance(configured, Mapping):
        raise ImproperlyConfigured(
            f"{AUTHZ_JSON_SCHEMAS_SETTING} must map schema_version values to package-anchored JSON Schema "
            f'resources, for example {{"1.0": "{AUTHZ_JSON_SCHEMA_V1_0}"}}. Got {configured!r}.'
        )
    unknown = sorted(str(version) for version in configured if version not in DEFAULT_AUTHZ_JSON_SCHEMAS)
    if unknown:
        raise ImproperlyConfigured(
            f"{AUTHZ_JSON_SCHEMAS_SETTING} can only override built-in schema versions "
            f"({', '.join(DEFAULT_AUTHZ_JSON_SCHEMAS)}), got {', '.join(unknown)}."
        )
    for version, resource in configured.items():
        if not isinstance(resource, str) or "/" not in resource:
            raise ImproperlyConfigured(
                f"{AUTHZ_JSON_SCHEMAS_SETTING}[{version!r}] must be a package-anchored JSON Schema resource "
                f'such as "{AUTHZ_JSON_SCHEMA_V1_0}", got {resource!r}.'
            )
    return MappingProxyType({**DEFAULT_AUTHZ_JSON_SCHEMAS, **configured})


def _version_key(version: str) -> tuple[int, ...]:
    """Order ``major.minor`` versions numerically, so ``"1.10"`` sorts after ``"1.9"``."""
    return tuple(int(part) for part in version.split("."))


class SchemaSyntaxValidator:
    """Collect JSON Schema findings for parsed documents."""

    def validate(self, documents: list[ParsedSchemaDocument]) -> list[ValidationIssue]:
        """Return every structural error from every parsed document."""
        validators = {
            version: document_validator(resource)
            for version, resource in sorted(
                configured_schema_resources().items(), key=lambda item: _version_key(item[0])
            )
        }
        latest = next(reversed(validators.values()))

        issues = []
        for document in documents:
            data = document.data
            if not isinstance(data, dict) or "schema_version" not in data:
                # Without a version to select by, the latest schema reports the missing field or
                # the wrong root type, along with any other structural error.
                issues.extend(self._errors(latest, document))
                continue

            version = data["schema_version"]
            validator = validators.get(version) if isinstance(version, str) else None
            if validator is None:
                issues.append(self._unsupported_version(version, validators, document))
                continue
            issues.extend(self._errors(validator, document))
        return issues

    @staticmethod
    def _errors(validator: Draft202012Validator, document: ParsedSchemaDocument) -> list[ValidationIssue]:
        """Return the JSON Schema errors of one document as validation issues."""
        return [
            ValidationIssue(IssueLevel.ERROR, f"{error.json_path}: {error.message}", document.source.source_id)
            for error in validator.iter_errors(document.data)
        ]

    @staticmethod
    def _unsupported_version(version: object, validators: dict, document: ParsedSchemaDocument) -> ValidationIssue:
        """Report a ``schema_version`` with no configured JSON Schema.

        The rest of the document is not checked, because its fields depend on the version.
        """
        supported = ", ".join(repr(supported_version) for supported_version in validators)
        message = f"$.schema_version: {version!r} is not a supported schema version. Supported versions: {supported}."
        if not isinstance(version, str):
            message += " Quote the value in YAML so it remains a string."
        return ValidationIssue(IssueLevel.ERROR, message, document.source.source_id)
