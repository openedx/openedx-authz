"""Tests for schema translation string extraction (ADR 0020).

The suite is grouped by the behaviour under test:

* ``TestRealSchemaExtraction`` -- extraction runs cleanly against the real,
  merged schema files and produces well-formed messages.
* ``TestFieldExtraction`` -- each schema entry type yields the right messages.
* ``TestContextDisambiguation`` -- identical text in different fields stays
  as separate messages, per ADR 0020.
* ``TestExtractionErrors`` -- malformed input is a hard error.
* ``TestRenderModule`` -- the generated module is valid, scannable Python.
"""

import pytest

from openedx_authz.engine.schema.discovery import SchemaDiscovery, SchemaDiscoveryError
from openedx_authz.engine.schema.translation import (
    SchemaTranslationExtractionError,
    TranslatableMessage,
    extract_messages,
    render_module,
)

SCHEMA_DIR = "openedx_authz/authz/schema"


class FakeResource:
    """A minimal stand-in for DiscoveredResource that reads from a string.

    extract_messages only ever calls read_bytes(), and reads .package/.resource_path
    for error messages, so this is all it needs; it avoids having to stand up a real
    importable package on disk for every synthetic/error-path test case.
    """

    def __init__(self, contents: str, package: str = "fake_pkg", resource_path: str = "schema/fake.yaml"):
        self._contents = contents
        self.package = package
        self.resource_path = resource_path

    def read_bytes(self) -> bytes:
        return self._contents.encode("utf-8")


def _resource(yaml_text: str) -> FakeResource:
    return FakeResource(yaml_text)


class TestRealSchemaExtraction:
    """Extraction against the real, already-merged schema files."""

    def test_extracts_messages_from_the_real_schema(self):
        """Running against the actual discovered schema yields well-formed messages."""
        resources = SchemaDiscovery(passed_in_directories=[SCHEMA_DIR]).discover()
        messages = extract_messages(resources)

        assert messages
        for message in messages:
            assert message.context
            assert ":" in message.context
            assert message.message

    def test_known_role_display_name_is_present(self):
        """A role we know exists in course_roles.yaml shows up with its real text."""
        resources = SchemaDiscovery(passed_in_directories=[SCHEMA_DIR]).discover()
        messages = {m.context: m.message for m in extract_messages(resources)}

        assert messages["role.display_name:course_admin"] == "Course Admin"

    def test_is_deterministic(self):
        """Extraction over the same input returns an identical, sorted list."""
        resources = SchemaDiscovery(passed_in_directories=[SCHEMA_DIR]).discover()
        assert extract_messages(resources) == extract_messages(resources)

    def test_default_resources_are_discovered_when_none_given(self):
        """Calling extract_messages() with no args discovers the real schema itself."""
        assert extract_messages() == extract_messages(SchemaDiscovery(passed_in_directories=[SCHEMA_DIR]).discover())


class TestFieldExtraction:
    """Each schema entry type yields the display_name/description messages it should."""

    def test_permission_category(self):
        messages = extract_messages([_resource("""
schema_version: "1.0"
priority: 100
permission_categories:
  - id: course_content
    display_name: Course content
    description: Permissions for viewing and editing course content.
""")])
        assert messages == [
            TranslatableMessage(
                "permission_category.description:course_content",
                "Permissions for viewing and editing course content.",
            ),
            TranslatableMessage("permission_category.display_name:course_content", "Course content"),
        ]

    def test_permission_stable_id_combines_namespace_and_name(self):
        messages = extract_messages([_resource("""
schema_version: "1.0"
priority: 100
permissions:
  - namespace: courses
    name: view_course
    display_name: View course
    description: View course configuration and content.
    category: course_content
    scopes: [course-v1]
""")])
        contexts = {m.context for m in messages}
        assert contexts == {
            "permission.display_name:courses.view_course",
            "permission.description:courses.view_course",
        }

    def test_role(self):
        messages = extract_messages([_resource("""
schema_version: "1.0"
priority: 100
roles:
  - id: course_observer
    display_name: Course observer
    description: Can review a course without changing it.
    scopes: [course-v1]
    permissions: [courses.view_course]
""")])
        contexts = {m.context: m.message for m in messages}
        assert contexts == {
            "role.display_name:course_observer": "Course observer",
            "role.description:course_observer": "Can review a course without changing it.",
        }

    def test_role_extension_only_emits_fields_it_actually_overrides(self):
        """A role_extension that doesn't touch display_name/description emits nothing for them."""
        messages = extract_messages([_resource("""
schema_version: "1.0"
priority: 100
role_extensions:
  - role: course_editor
    add_permissions: [courses.export_course]
""")])
        assert messages == []

    def test_role_extension_with_overrides(self):
        messages = extract_messages([_resource("""
schema_version: "1.0"
priority: 100
role_extensions:
  - role: course_editor
    display_name: Course author
    description: Creates and exports course content.
""")])
        contexts = {m.context: m.message for m in messages}
        assert contexts == {
            "role_extension.display_name:course_editor": "Course author",
            "role_extension.description:course_editor": "Creates and exports course content.",
        }

    def test_missing_entries_are_fine(self):
        """A file that only defines some blocks doesn't error on the missing ones."""
        messages = extract_messages([_resource("""
schema_version: "1.0"
priority: 100
roles:
  - id: course_observer
    display_name: Course observer
    description: Can review a course without changing it.
""")])
        assert len(messages) == 2


class TestContextDisambiguation:
    """ADR 0020: identical English text in different fields stays separate."""

    def test_identical_display_name_and_description_text_stay_separate(self):
        """A display_name and description that happen to be identical text don't merge."""
        messages = extract_messages([_resource("""
schema_version: "1.0"
priority: 100
roles:
  - id: course_admin
    display_name: Admin
    description: Admin
    scopes: [course-v1]
""")])
        assert len(messages) == 2
        assert messages[0].message == messages[1].message == "Admin"
        assert messages[0].context != messages[1].context

    def test_same_display_name_text_across_different_roles_stays_separate(self):
        """Two different roles sharing display text ("Admin") get distinct contexts."""
        messages = extract_messages([_resource("""
schema_version: "1.0"
priority: 100
roles:
  - id: course_admin
    display_name: Admin
    scopes: [course-v1]
  - id: library_admin
    display_name: Admin
    scopes: [lib]
""")])
        display_name_messages = [m for m in messages if m.context.startswith("role.display_name:")]
        assert len(display_name_messages) == 2
        assert {m.context for m in display_name_messages} == {
            "role.display_name:course_admin",
            "role.display_name:library_admin",
        }


class TestExtractionErrors:
    """Malformed schema input is a hard error, not a silent skip (ADR 0020)."""

    def test_invalid_yaml_raises(self):
        with pytest.raises(SchemaTranslationExtractionError):
            extract_messages([_resource("roles: [this is: not: valid: yaml")])

    def test_non_mapping_top_level_raises(self):
        with pytest.raises(SchemaTranslationExtractionError):
            extract_messages([_resource("- just\n- a\n- list\n")])

    def test_unreadable_resource_raises(self):
        class BrokenResource(FakeResource):
            def read_bytes(self) -> bytes:
                raise SchemaDiscoveryError("could not read resource")

        with pytest.raises(SchemaTranslationExtractionError):
            extract_messages([BrokenResource("")])

    def test_discovery_failure_propagates_when_resources_not_given(self, monkeypatch):
        def _raise():
            raise SchemaDiscoveryError("boom")

        monkeypatch.setattr(SchemaDiscovery, "discover", lambda self: _raise())

        with pytest.raises(SchemaTranslationExtractionError):
            extract_messages()


class TestRenderModule:
    """The generated module is valid, scannable Python source."""

    def test_output_is_valid_python(self):
        messages = [
            TranslatableMessage("role.display_name:course_admin", "Course Admin"),
            TranslatableMessage("role.description:course_admin", "Can manage everything."),
        ]
        source = render_module(messages)
        compile(source, "<generated>", "exec")  # Raises SyntaxError if malformed.

    def test_strings_with_quotes_and_newlines_are_escaped_safely(self):
        """repr()-based rendering must survive content a naive f-string would break on."""
        messages = [TranslatableMessage("role.description:tricky", 'Has "quotes", a \'single\' and\na newline.')]
        source = render_module(messages)
        compile(source, "<generated>", "exec")
        assert 'Has "quotes"' in source or "quotes" in source

    def test_empty_message_list_is_still_valid_python(self):
        compile(render_module([]), "<generated>", "exec")

    def test_output_contains_do_not_edit_warning(self):
        assert "Do not edit" in render_module([])
