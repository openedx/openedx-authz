"""Tests for parsing schema resources without imposing document structure."""

from __future__ import annotations

import hashlib

import pytest

from openedx_authz.engine.schema.exceptions import SchemaLoadError
from openedx_authz.engine.schema.parsing import SchemaParser
from openedx_authz.tests.schema.factories import InMemoryResource


@pytest.mark.parametrize(
    ("contents", "expected"),
    [
        (b"schema_version: '1.0'\npriority: 10\n", {"schema_version": "1.0", "priority": 10}),
        (b"value", "value"),
        (b"- first\n- second\n", ["first", "second"]),
    ],
)
def test_parser_preserves_yaml_value(contents, expected):
    """The parser preserves each YAML root value for structural validation."""
    document = SchemaParser().parse([InMemoryResource(contents)])[0]

    assert document.data == expected


def test_parser_rejects_malformed_yaml():
    """Malformed YAML remains a parsing error compatible with SchemaLoadError."""
    resource = InMemoryResource(b"schema_version: '1.0'\n  bad: [unclosed\n")

    with pytest.raises(SchemaLoadError, match="Invalid YAML"):
        SchemaParser().parse([resource])


def test_parser_records_provenance_and_exact_content_digest(monkeypatch):
    """Parsed documents retain package provenance and hash the bytes read."""
    contents = b"schema_version: '1.0'\npriority: 10\n"
    resource = InMemoryResource(contents, package="example", module="example.authz", resource_path="roles.yml")
    monkeypatch.setattr("openedx_authz.engine.schema.parsing.metadata.packages_distributions", lambda: {})

    document = SchemaParser().parse([resource])[0]

    assert document.source.distribution == "example"
    assert document.source.distribution_version == "unknown"
    assert document.source.module == "example.authz"
    assert document.source.resource_path == "roles.yml"
    assert document.source.schema_version == "1.0"
    assert document.source.content_digest == hashlib.sha256(contents).hexdigest()
