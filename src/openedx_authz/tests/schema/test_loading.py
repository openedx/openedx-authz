"""Unit tests for the schema loading step."""

import logging
from importlib import metadata

import pytest

from openedx_authz.engine.schema.discovery import DiscoveredResource, Origin, SchemaDiscovery
from openedx_authz.engine.schema.exceptions import SchemaLoadError
from openedx_authz.engine.schema.loading import SchemaLoader

from .factories import InMemoryResource

UNKNOWN_DISTRIBUTION = SchemaLoader._UNKNOWN_DISTRIBUTION  # pylint: disable=protected-access

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
    category_id: course_content
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
  - role_id: course_editor
    add_permissions: [courses.export_course]
"""


def _load(contents: bytes):
    resource = InMemoryResource(contents, package="pkg", module="pkg.mod")
    return SchemaLoader().load([resource])


class TestDocumentLoading:
    """Parsing a schema file into a typed :class:`SchemaDocument`.

    Covers the happy path (every block populated), the degenerate empty inputs
    the loader must tolerate (validation rejects them later, not loading), and
    the structural failures that must stop the load.
    """

    def test_loads_all_blocks_into_typed_objects(self):
        """Every top-level block becomes its typed object with fields intact."""
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
        assert doc.role_extensions[0].role_id == "course_editor"
        assert doc.role_extensions[0].add_permissions == ("courses.export_course",)

    def test_extension_changes_are_loaded(self):
        """A ``role_extensions`` entry's edits (adds, removes, metadata) round-trip.

        ``test_loads_all_blocks_into_typed_objects`` only exercises an add; this
        pins the remove/rename/hide edits an extension can carry (ADR 0023).
        """
        docs = _load(
            b"schema_version: '1.0'\n"
            b"priority: 200\n"
            b"role_extensions:\n"
            b"  - role_id: course_editor\n"
            b"    add_permissions: [courses.export_course]\n"
            b"    remove_permissions: [courses.manage_tags]\n"
            b"    display_name: Course author\n"
            b"    description: Creates and exports course content.\n"
            b"    hidden: true\n"
        )

        extension = docs[0].role_extensions[0]
        assert extension.role_id == "course_editor"
        assert extension.add_permissions == ("courses.export_course",)
        assert extension.remove_permissions == ("courses.manage_tags",)
        assert extension.display_name == "Course author"
        assert extension.description == "Creates and exports course content."
        assert extension.hidden is True

    def test_empty_document_yields_empty_blocks(self):
        """A file with only header fields yields empty block lists, not errors."""
        docs = _load(b"schema_version: '1.0'\npriority: 1\n")
        assert docs[0].categories == []
        assert docs[0].roles == []

    def test_completely_empty_file_is_treated_as_an_empty_mapping(self):
        """An empty file parses to ``None``; validation rejects it, loading must not."""
        docs = _load(b"")

        assert docs[0].priority == 0
        assert docs[0].source.schema_version == ""
        assert docs[0].roles == []

    def test_invalid_yaml_raises_load_error(self):
        """Malformed YAML surfaces as ``SchemaLoadError``."""
        with pytest.raises(SchemaLoadError):
            _load(b"schema_version: '1.0'\n  bad: [unclosed\n")

    def test_non_mapping_top_level_raises_load_error(self):
        """A top-level sequence (not a mapping) is rejected."""
        with pytest.raises(SchemaLoadError):
            _load(b"- just\n- a\n- list\n")

    def test_non_integer_priority_raises_load_error(self):
        """A non-numeric priority is a mistake, not a default."""
        with pytest.raises(SchemaLoadError):
            _load(b"schema_version: '1.0'\npriority: high\n")


class TestSourceIdentity:
    """``(distribution, module)`` is the identity of a source record (ADR 0025 §2).

    The rest of the suite builds ``SourceRecord`` values through factories, so
    these tests are the only ones that exercise the real resolution against
    installed package metadata.
    """

    @staticmethod
    def _fake_distribution_lookup(files_by_name):
        """Build a ``metadata.distribution`` replacement backed by preset file lists.

        ``files_by_name`` maps a distribution name to the anchor-relative paths
        it records; the returned callable exposes those via a ``.files``
        attribute, mimicking ``importlib.metadata.Distribution``. Names absent
        from the mapping raise ``PackageNotFoundError``, as the real backend
        does for an uninstalled distribution.
        """

        class _Distribution:
            def __init__(self, files):
                self.files = files

        def _distribution(name):
            if name not in files_by_name:
                raise metadata.PackageNotFoundError(name)
            return _Distribution(files_by_name[name])

        return _distribution

    def test_installed_package_resolves_to_its_distribution(self):
        """A module shipped by this package resolves to the real distribution."""
        discovery = SchemaDiscovery(passed_in_directories=["openedx_authz/authz/schema"])
        docs = SchemaLoader().load(discovery.discover())

        assert {doc.source.distribution for doc in docs} == {"openedx-authz"}
        assert all(doc.source.distribution_version != UNKNOWN_DISTRIBUTION for doc in docs)

    def test_module_is_recorded_as_the_dotted_path(self):
        """The source module is recorded as the resource's dotted import path."""
        discovery = SchemaDiscovery(passed_in_directories=["openedx_authz/authz/schema"])
        docs = SchemaLoader().load(discovery.discover())

        assert {doc.source.module for doc in docs} == {"openedx_authz.authz.schema"}

    def test_unknown_package_falls_back_to_its_top_level_name(self):
        """An operator-supplied directory need not belong to a distribution."""
        docs = _load(b"schema_version: '1.0'\npriority: 1\n")

        assert docs[0].source.distribution == "pkg"
        assert docs[0].source.distribution_version == UNKNOWN_DISTRIBUTION

    def test_missing_distribution_metadata_falls_back_to_unknown_version(self, monkeypatch):
        """A distribution with no readable version falls back to ``UNKNOWN``."""
        monkeypatch.setattr(metadata, "packages_distributions", lambda: {"pkg": ["ghost-dist"]})

        def _missing(_name):
            raise metadata.PackageNotFoundError("ghost-dist")

        monkeypatch.setattr(metadata, "version", _missing)

        docs = _load(b"schema_version: '1.0'\npriority: 1\n")

        assert docs[0].source.distribution == "ghost-dist"
        assert docs[0].source.distribution_version == UNKNOWN_DISTRIBUTION

    def test_unreadable_package_metadata_is_tolerated(self, monkeypatch):
        """Environment quirks must not break the loader."""

        def _boom():
            raise RuntimeError("metadata backend unavailable")

        monkeypatch.setattr(metadata, "packages_distributions", _boom)

        docs = _load(b"schema_version: '1.0'\npriority: 1\n")

        assert docs[0].source.distribution == "pkg"

    def test_multiple_candidates_resolve_to_the_distribution_that_ships_the_file(self, monkeypatch):
        """When several distributions claim the top-level package, pick the file's owner.

        ``packages_distributions`` returns a list because a top-level import
        package can be provided by more than one distribution (namespace
        packages, overlapping installs). The owner is the one whose recorded
        file list actually contains the resource (ADR 0019 §2), not the first
        list entry.
        """
        monkeypatch.setattr(metadata, "packages_distributions", lambda: {"pkg": ["other-dist", "owning-dist"]})
        monkeypatch.setattr(
            metadata, "distribution", self._fake_distribution_lookup({"owning-dist": ["pkg/file.authz.yaml"]})
        )
        monkeypatch.setattr(metadata, "version", lambda name: "9.9" if name == "owning-dist" else "0.0")

        docs = _load(b"schema_version: '1.0'\npriority: 1\n")

        assert docs[0].source.distribution == "owning-dist"
        assert docs[0].source.distribution_version == "9.9"

    def test_ambiguous_ownership_falls_back_to_a_deterministic_choice(self, monkeypatch):
        """With no single file owner, pick the first candidate in sorted order.

        If zero or more than one candidate claims the file (or file lists are
        unavailable), the true owner is unknown. The pick must still be stable
        across environments, so it is sorted rather than discovery-ordered.
        """
        monkeypatch.setattr(metadata, "packages_distributions", lambda: {"pkg": ["zed-dist", "alpha-dist"]})
        # Neither distribution records the file, so ownership cannot be confirmed.
        monkeypatch.setattr(metadata, "distribution", self._fake_distribution_lookup({}))
        monkeypatch.setattr(metadata, "version", lambda _name: "1.0")

        docs = _load(b"schema_version: '1.0'\npriority: 1\n")

        assert docs[0].source.distribution == "alpha-dist"

    def test_digest_reflects_the_file_contents(self):
        """Different file contents produce different content digests."""
        first = _load(b"schema_version: '1.0'\npriority: 1\n")[0]
        second = _load(b"schema_version: '1.0'\npriority: 2\n")[0]

        assert first.source.content_digest != second.source.content_digest

    def test_identical_contents_produce_the_same_digest(self):
        """Identical file contents produce the same content digest."""
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
        """A YAML block whose value is null coerces to an empty list."""
        docs = _load(b"schema_version: '1.0'\npriority: 1\nroles:\npermissions:\n")

        assert docs[0].roles == []
        assert docs[0].permissions == []

    def test_missing_priority_defaults_to_zero(self):
        """``priority`` is required by the schema, but the loader defers that.

        Enforcing required fields is the validate step's job (ADR 0018), so the
        loader reads a missing ``priority`` as ``0`` rather than raising; a
        later validation pass rejects the omission.
        """
        docs = _load(b"schema_version: '1.0'\n")

        assert docs[0].priority == 0

    def test_missing_schema_version_is_empty_not_absent(self):
        """Validation rejects it later; the loader must not crash on it."""
        docs = _load(b"priority: 1\n")

        assert docs[0].source.schema_version == ""

    def test_numeric_string_priority_is_accepted(self):
        """A priority written as a numeric string is coerced to an int."""
        docs = _load(b"schema_version: '1.0'\npriority: '150'\n")

        assert docs[0].priority == 150

    def test_extension_hidden_false_is_preserved_as_a_change(self):
        """``hidden`` is tri-state: ``False`` differs from absent (ADR 0023 §1)."""
        docs = _load(
            b"schema_version: '1.0'\npriority: 1\nrole_extensions:\n  - role_id: course_editor\n    hidden: false\n"
        )

        assert docs[0].role_extensions[0].hidden is False

    def test_extension_without_hidden_leaves_it_unset(self):
        """An extension that omits ``hidden`` leaves it ``None`` (unchanged)."""
        docs = _load(
            b"schema_version: '1.0'\npriority: 1\nrole_extensions:\n  - role_id: course_editor\n    icon: Article\n"
        )

        assert docs[0].role_extensions[0].hidden is None


class TestMalformedEntries:
    """A block entry that is not a mapping stops the load with context."""

    @pytest.mark.parametrize("block", ["permission_categories", "permissions", "roles", "role_extensions"])
    def test_non_mapping_entry_raises_with_the_block_name(self, block):
        """A non-mapping entry in any block raises an error naming that block."""
        contents = f"schema_version: '1.0'\npriority: 1\n{block}:\n  - just_a_string\n".encode()

        with pytest.raises(SchemaLoadError, match=block):
            _load(contents)

    def test_error_names_the_source(self):
        """A malformed entry error names the contributing source."""
        with pytest.raises(SchemaLoadError, match="pkg.mod"):
            _load(b"schema_version: '1.0'\npriority: 1\nroles:\n  - 5\n")


@pytest.fixture
def clear_warned_distributions() -> None:
    """Clear the class-level distribution ambiguity tracker before and after each test.

    Ensures test isolation and order-independence by resetting the dedupe set
    that prevents duplicate logging of the same ambiguity.
    """
    SchemaLoader._distribution_ambiguity_warned.clear()  # pylint: disable=protected-access
    yield
    SchemaLoader._distribution_ambiguity_warned.clear()  # pylint: disable=protected-access


class TestDistributionAmbiguityLogging:
    """Test distribution resolution logging and deduplication.

    When multiple distributions claim the same top-level package, the loader
    must select one deterministically and log the ambiguity exactly once per
    distinct (package, resource_path, selected) combination.
    """

    def test_single_candidate_no_log(
        self,
        clear_warned_distributions: None,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """When there is a single candidate, no ambiguity log is emitted."""
        caplog.set_level(logging.INFO)
        resource = DiscoveredResource(
            package="test_package",
            resource_path="schema/test.yaml",
            module="test_package.schema",
            origin=Origin.ENTRY_POINT,
        )

        result = SchemaLoader._select_owning_distribution(["dist1"], resource)  # pylint: disable=protected-access

        assert result == "dist1"
        assert len(caplog.records) == 0

    def test_unique_owner_no_log(
        self,
        clear_warned_distributions: None,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When ownership can be uniquely resolved, no ambiguity log is emitted."""
        caplog.set_level(logging.INFO)
        resource = DiscoveredResource(
            package="test_package",
            resource_path="schema/test.yaml",
            module="test_package.schema",
            origin=Origin.ENTRY_POINT,
        )

        # Mock _distribution_ships so only dist1 claims the resource
        def mock_ships(distribution: str, installed_path: str) -> bool:
            return distribution == "dist1"

        monkeypatch.setattr(SchemaLoader, "_distribution_ships", staticmethod(mock_ships))

        result = SchemaLoader._select_owning_distribution(["dist1", "dist2"], resource)  # pylint: disable=protected-access

        assert result == "dist1"
        assert len(caplog.records) == 0

    def test_ambiguous_fallback_logs_once(
        self,
        clear_warned_distributions: None,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When ownership is ambiguous, a single info-level log is emitted."""
        caplog.set_level(logging.INFO)
        resource = DiscoveredResource(
            package="test_package",
            resource_path="schema/test.yaml",
            module="test_package.schema",
            origin=Origin.ENTRY_POINT,
        )

        # Mock _distribution_ships so no distribution claims the resource
        monkeypatch.setattr(SchemaLoader, "_distribution_ships", staticmethod(lambda *args: False))

        SchemaLoader._select_owning_distribution(["dist2", "dist1"], resource)  # pylint: disable=protected-access

        # Should emit exactly one log record
        assert len(caplog.records) == 1
        assert caplog.records[0].levelno == logging.INFO
        assert caplog.records[0].levelname == "INFO"

    def test_log_message_includes_distribution(
        self,
        clear_warned_distributions: None,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Log message includes the selected distribution name and package."""
        caplog.set_level(logging.INFO)
        resource = DiscoveredResource(
            package="test_package",
            resource_path="schema/test.yaml",
            module="test_package.schema",
            origin=Origin.ENTRY_POINT,
        )
        monkeypatch.setattr(SchemaLoader, "_distribution_ships", staticmethod(lambda *args: False))

        result = SchemaLoader._select_owning_distribution(["dist2", "dist1"], resource)  # pylint: disable=protected-access

        assert result == "dist1"
        log_msg = caplog.records[0].message
        assert "dist1" in log_msg
        assert "test_package" in log_msg

    def test_log_extra_dict_preserved(
        self,
        clear_warned_distributions: None,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Log record preserves all structured context in the 'extra' dict."""
        caplog.set_level(logging.INFO)
        resource = DiscoveredResource(
            package="test_package",
            resource_path="schema/test.yaml",
            module="test_package.schema",
            origin=Origin.ENTRY_POINT,
        )
        monkeypatch.setattr(SchemaLoader, "_distribution_ships", staticmethod(lambda *args: False))

        SchemaLoader._select_owning_distribution(["dist2", "dist1"], resource)  # pylint: disable=protected-access

        record = caplog.records[0]
        assert hasattr(record, "top_level")
        assert record.top_level == "test_package"
        assert hasattr(record, "resource_path")
        assert record.resource_path == "schema/test.yaml"
        assert hasattr(record, "candidates")
        assert set(record.candidates) == {"dist1", "dist2"}
        assert hasattr(record, "matched_owners")
        assert record.matched_owners == []
        assert hasattr(record, "selected")
        assert record.selected == "dist1"

    def test_same_ambiguity_logged_only_once(
        self,
        clear_warned_distributions: None,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Identical (package, resource_path, selected) combinations log only once.

        This tests the deduplication behavior across multiple calls within
        the same process.
        """
        caplog.set_level(logging.INFO)
        monkeypatch.setattr(SchemaLoader, "_distribution_ships", staticmethod(lambda *args: False))

        resource = DiscoveredResource(
            package="test_package",
            resource_path="schema/test.yaml",
            module="test_package.schema",
            origin=Origin.ENTRY_POINT,
        )

        # Call multiple times with the same resource
        for _ in range(3):
            SchemaLoader._select_owning_distribution(["dist2", "dist1"], resource)  # pylint: disable=protected-access

        # Should emit exactly one log record despite three calls
        assert len(caplog.records) == 1

    def test_different_resources_each_logged(
        self,
        clear_warned_distributions: None,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Different resources (even with same candidates) each log once."""
        caplog.set_level(logging.INFO)
        monkeypatch.setattr(SchemaLoader, "_distribution_ships", staticmethod(lambda *args: False))

        resource1 = DiscoveredResource(
            package="test_package",
            resource_path="schema/test1.yaml",
            module="test_package.schema",
            origin=Origin.ENTRY_POINT,
        )
        resource2 = DiscoveredResource(
            package="test_package",
            resource_path="schema/test2.yaml",
            module="test_package.schema",
            origin=Origin.ENTRY_POINT,
        )

        SchemaLoader._select_owning_distribution(["dist2", "dist1"], resource1)  # pylint: disable=protected-access
        SchemaLoader._select_owning_distribution(["dist2", "dist1"], resource2)  # pylint: disable=protected-access

        # Should emit two log records (one per unique resource_path)
        assert len(caplog.records) == 2

    def test_selection_logic_unchanged(
        self,
        clear_warned_distributions: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Fallback selection is still deterministic (sorted first candidate)."""
        resource = DiscoveredResource(
            package="test_package",
            resource_path="schema/test.yaml",
            module="test_package.schema",
            origin=Origin.ENTRY_POINT,
        )
        # Test with various orderings; should always return sorted[0]
        monkeypatch.setattr(SchemaLoader, "_distribution_ships", staticmethod(lambda *args: False))

        candidates = ["zebra", "apple", "banana"]

        result = SchemaLoader._select_owning_distribution(candidates, resource)  # pylint: disable=protected-access

        assert result == "apple"  # sorted(candidates)[0]

    def test_log_level_is_info_not_warning(
        self,
        clear_warned_distributions: None,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Log level is INFO, not WARNING, for the ambiguity."""
        caplog.set_level(logging.DEBUG)
        resource = DiscoveredResource(
            package="test_package",
            resource_path="schema/test.yaml",
            module="test_package.schema",
            origin=Origin.ENTRY_POINT,
        )
        monkeypatch.setattr(SchemaLoader, "_distribution_ships", staticmethod(lambda *args: False))

        SchemaLoader._select_owning_distribution(["dist2", "dist1"], resource)  # pylint: disable=protected-access

        assert len(caplog.records) == 1
        record = caplog.records[0]
        assert record.levelno == logging.INFO
        assert record.levelname == "INFO"

    def test_dedupe_key_includes_selected_distribution(
        self,
        clear_warned_distributions: None,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Deduplication key depends on the selected distribution.

        Since sorting is deterministic, the same candidates always yield
        the same fallback, so we verify that identical candidates produce
        identical fallbacks and thus deduplicate.
        """
        caplog.set_level(logging.INFO)
        monkeypatch.setattr(SchemaLoader, "_distribution_ships", staticmethod(lambda *args: False))

        resource = DiscoveredResource(
            package="test_package",
            resource_path="schema/test.yaml",
            module="test_package.schema",
            origin=Origin.ENTRY_POINT,
        )

        # Both orderings should select the same deterministic fallback
        result1 = SchemaLoader._select_owning_distribution(["dist2", "dist1"], resource)  # pylint: disable=protected-access
        result2 = SchemaLoader._select_owning_distribution(["dist1", "dist2"], resource)  # pylint: disable=protected-access

        assert result1 == result2 == "dist1"
        # Only one log record because the warn_key is identical
        assert len(caplog.records) == 1
