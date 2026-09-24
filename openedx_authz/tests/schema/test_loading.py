"""Unit tests for the schema loading step."""

from importlib import metadata

import pytest

from openedx_authz.engine.schema.discovery import SchemaDiscovery
from openedx_authz.engine.schema.exceptions import SchemaLoadError
from openedx_authz.engine.schema.loading import UNKNOWN, SchemaLoader

from .factories import InMemoryResource

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
    resource = InMemoryResource(contents, package="pkg", module="pkg.mod")
    return SchemaLoader().load([resource])


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


def test_completely_empty_file_is_treated_as_an_empty_mapping():
    """An empty file parses to ``None``; validation rejects it, loading must not."""
    docs = _load(b"")

    assert docs[0].priority == 0
    assert docs[0].source.schema_version == ""
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


class TestSourceIdentity:
    """``(distribution, module)`` is the identity of a source record (ADR 0025 §2).

    The rest of the suite builds ``SourceRecord`` values through factories, so
    these tests are the only ones that exercise the real resolution against
    installed package metadata.
    """

    def test_installed_package_resolves_to_its_distribution(self):
        """A module shipped by this package resolves to the real distribution."""
        discovery = SchemaDiscovery(passed_in_directories=["openedx_authz/authz/schema"])
        docs = SchemaLoader().load(discovery.discover())

        assert {doc.source.distribution for doc in docs} == {"openedx-authz"}
        assert all(doc.source.distribution_version != UNKNOWN for doc in docs)

    def test_module_is_recorded_as_the_dotted_path(self):
        discovery = SchemaDiscovery(passed_in_directories=["openedx_authz/authz/schema"])
        docs = SchemaLoader().load(discovery.discover())

        assert {doc.source.module for doc in docs} == {"openedx_authz.authz.schema"}

    def test_unknown_package_falls_back_to_its_top_level_name(self):
        """An operator-supplied directory need not belong to a distribution."""
        docs = _load(b"schema_version: '1.0'\npriority: 1\n")

        assert docs[0].source.distribution == "pkg"
        assert docs[0].source.distribution_version == UNKNOWN

    def test_missing_distribution_metadata_falls_back_to_unknown_version(self, monkeypatch):
        monkeypatch.setattr(metadata, "packages_distributions", lambda: {"pkg": ["ghost-dist"]})

        def _missing(_name):
            raise metadata.PackageNotFoundError("ghost-dist")

        monkeypatch.setattr(metadata, "version", _missing)

        docs = _load(b"schema_version: '1.0'\npriority: 1\n")

        assert docs[0].source.distribution == "ghost-dist"
        assert docs[0].source.distribution_version == UNKNOWN

    def test_unreadable_package_metadata_is_tolerated(self, monkeypatch):
        """Environment quirks must not break the loader."""

        def _boom():
            raise RuntimeError("metadata backend unavailable")

        monkeypatch.setattr(metadata, "packages_distributions", _boom)

        docs = _load(b"schema_version: '1.0'\npriority: 1\n")

        assert docs[0].source.distribution == "pkg"

    def test_digest_reflects_the_file_contents(self):
        first = _load(b"schema_version: '1.0'\npriority: 1\n")[0]
        second = _load(b"schema_version: '1.0'\npriority: 2\n")[0]

        assert first.source.content_digest != second.source.content_digest

    def test_identical_contents_produce_the_same_digest(self):
        first = _load(b"schema_version: '1.0'\npriority: 1\n")[0]
        second = _load(b"schema_version: '1.0'\npriority: 1\n")[0]

        assert first.source.content_digest == second.source.content_digest


class TestFieldCoercion:
    """Loader-level normalization of YAML shapes."""

    def test_scalar_scope_becomes_a_one_tuple(self):
        """``scopes: course-v1`` is accepted as shorthand for a single-item list."""
        docs = _load(
            b"schema_version: '1.0'\n"
            b"priority: 1\n"
            b"roles:\n"
            b"  - id: course_observer\n"
            b"    scopes: course-v1\n"
            b"    permissions: courses.view_course\n"
        )

        assert docs[0].roles[0].scopes == ("course-v1",)
        assert docs[0].roles[0].permissions == ("courses.view_course",)

    def test_null_blocks_are_treated_as_empty(self):
        docs = _load(b"schema_version: '1.0'\npriority: 1\nroles:\npermissions:\n")

        assert docs[0].roles == []
        assert docs[0].permissions == []

    def test_missing_priority_defaults_to_zero(self):
        """Priority decides every conflict, so the default is worth pinning down."""
        docs = _load(b"schema_version: '1.0'\n")

        assert docs[0].priority == 0

    def test_missing_schema_version_is_empty_not_absent(self):
        """Validation rejects it later; the loader must not crash on it."""
        docs = _load(b"priority: 1\n")

        assert docs[0].source.schema_version == ""

    def test_numeric_string_priority_is_accepted(self):
        docs = _load(b"schema_version: '1.0'\npriority: '150'\n")

        assert docs[0].priority == 150

    def test_extension_hidden_false_is_preserved_as_a_change(self):
        """``hidden`` is tri-state: ``False`` differs from absent (ADR 0023 §1)."""
        docs = _load(
            b"schema_version: '1.0'\npriority: 1\nrole_extensions:\n  - role: course_editor\n    hidden: false\n"
        )

        assert docs[0].role_extensions[0].hidden is False

    def test_extension_without_hidden_leaves_it_unset(self):
        docs = _load(
            b"schema_version: '1.0'\npriority: 1\nrole_extensions:\n  - role: course_editor\n    icon: Article\n"
        )

        assert docs[0].role_extensions[0].hidden is None


class TestMalformedEntries:
    """A block entry that is not a mapping stops the load with context."""

    @pytest.mark.parametrize("block", ["permission_categories", "permissions", "roles", "role_extensions"])
    def test_non_mapping_entry_raises_with_the_block_name(self, block):
        contents = f"schema_version: '1.0'\npriority: 1\n{block}:\n  - just_a_string\n".encode()

        with pytest.raises(SchemaLoadError, match=block):
            _load(contents)

    def test_error_names_the_source(self):
        with pytest.raises(SchemaLoadError, match="pkg.mod"):
            _load(b"schema_version: '1.0'\npriority: 1\nroles:\n  - 5\n")
