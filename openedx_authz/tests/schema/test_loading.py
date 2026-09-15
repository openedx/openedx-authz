"""Unit tests for the schema loading step."""

import pytest

from openedx_authz.engine.schema.exceptions import SchemaLoadError
from openedx_authz.engine.schema.loading import SchemaLoader

from .factories import StubDiscovery

VALID_YAML = b"""
schema_version: "1.0"
priority: 150

permission_categories:
  - id: course_content
    display_name: Course content
    description: Course content permissions.
    icon: Article

permissions:
  - namespace: courses
    name: view_course
    display_name: View course
    description: View a course.
    category: course_content
    scopes: [course-v1]

roles:
  - id: course_observer
    display_name: Course observer
    description: Reviews a course.
    scopes: [course-v1]
    hidden: true
    permissions:
      - courses.view_course

role_extensions:
  - role: course_editor
    add_permissions: [courses.export_course]
"""


def _load(contents: bytes):
    key = ("pkg.mod", "file.authz.yaml")
    discovery = StubDiscovery({key: contents})
    loader = SchemaLoader(discovery=discovery)
    return loader.load(discovery.discover())


def test_loads_all_blocks_into_typed_objects():
    docs = _load(VALID_YAML)
    assert len(docs) == 1
    doc = docs[0]
    assert doc.priority == 150
    assert doc.source.schema_version == "1.0"
    assert doc.source.content_digest  # digest computed
    assert doc.categories[0].id == "course_content"
    assert doc.permissions[0].identifier == "courses.view_course"
    assert doc.permissions[0].scopes == ("course-v1",)
    assert doc.roles[0].hidden is True
    assert doc.roles[0].permissions == ("courses.view_course",)
    assert doc.role_extensions[0].role == "course_editor"
    assert doc.role_extensions[0].add_permissions == ("courses.export_course",)


def test_empty_document_yields_empty_blocks():
    docs = _load(b"schema_version: '1.0'\npriority: 1\n")
    assert docs[0].categories == []
    assert docs[0].roles == []


def test_invalid_yaml_raises_load_error():
    with pytest.raises(SchemaLoadError):
        _load(b"schema_version: '1.0'\n  bad: [unclosed\n")


def test_non_mapping_top_level_raises_load_error():
    with pytest.raises(SchemaLoadError):
        _load(b"- just\n- a\n- list\n")


def test_non_integer_priority_raises_load_error():
    with pytest.raises(SchemaLoadError):
        _load(b"schema_version: '1.0'\npriority: high\n")
