"""Unit tests for the schema compilation step (merge + extensions + priority)."""

import logging

import pytest

from openedx_authz.engine.schema.compilation import SchemaCompiler
from openedx_authz.engine.schema.exceptions import SchemaCompileError
from openedx_authz.engine.schema.types import ORIGIN_BASE, ORIGIN_EXTENSION

from .factories import category, extension, make_document, make_source, permission, role

PERMS = [
    permission(name="view_course", cat="cat"),
    permission(name="export_course", cat="cat"),
    permission(name="manage_tags", cat="cat"),
]


def _base(**role_kwargs):
    return make_document(
        "base",
        priority=100,
        categories=[category("cat")],
        permissions=PERMS,
        roles=[role(rid="course_editor", permissions=("courses.view_course", "courses.manage_tags"), **role_kwargs)],
    )


def test_base_definitions_compile():
    schema = SchemaCompiler().compile([_base()])
    assert set(schema.roles) == {"course_editor"}
    assert len(schema.permissions) == 3
    # Base definitions keep their declared order; rendering sorts later.
    assert schema.roles["course_editor"].definition.permissions == (
        "courses.view_course",
        "courses.manage_tags",
    )


def test_extension_adds_and_removes_permissions_and_metadata():
    ext = make_document(
        "ext",
        priority=200,
        role_extensions=[
            extension(
                "course_editor",
                add_permissions=("courses.export_course",),
                remove_permissions=("courses.manage_tags",),
                display_name="Author",
                hidden=True,
            )
        ],
    )
    definition = SchemaCompiler().compile([_base(), ext]).roles["course_editor"].definition
    assert "courses.export_course" in definition.permissions
    assert "courses.manage_tags" not in definition.permissions
    assert definition.display_name == "Author"
    assert definition.hidden is True


def test_extension_sources_are_retained():
    ext = make_document("ext", priority=200, role_extensions=[extension("course_editor", display_name="X")])
    compiled = SchemaCompiler().compile([_base(), ext])
    assert len(compiled.roles["course_editor"].sources) == 2


def test_equal_priority_metadata_conflict_raises():
    a = make_document("a", priority=200, role_extensions=[extension("course_editor", display_name="A")])
    b = make_document("b", priority=200, role_extensions=[extension("course_editor", display_name="B")])
    with pytest.raises(SchemaCompileError):
        SchemaCompiler().compile([_base(), a, b])


def test_higher_priority_metadata_wins():
    lo = make_document("lo", priority=150, role_extensions=[extension("course_editor", display_name="Lo")])
    hi = make_document("hi", priority=300, role_extensions=[extension("course_editor", display_name="Hi")])
    definition = SchemaCompiler().compile([_base(), lo, hi]).roles["course_editor"].definition
    assert definition.display_name == "Hi"


def test_equal_priority_add_remove_conflict_raises():
    add = make_document(
        "add",
        priority=200,
        role_extensions=[extension("course_editor", add_permissions=("courses.export_course",))],
    )
    rem = make_document(
        "rem",
        priority=200,
        role_extensions=[extension("course_editor", remove_permissions=("courses.export_course",))],
    )
    with pytest.raises(SchemaCompileError):
        SchemaCompiler().compile([_base(), add, rem])


def test_conflicting_base_definition_equal_priority_raises():
    a = make_document("a", priority=100, roles=[role(rid="dup", display_name="A", permissions=())])
    b = make_document("b", priority=100, roles=[role(rid="dup", display_name="B", permissions=())])
    with pytest.raises(SchemaCompileError):
        SchemaCompiler().compile([a, b])


def test_higher_priority_base_definition_wins():
    lo = make_document("lo", priority=100, roles=[role(rid="dup", display_name="Lo", permissions=())])
    hi = make_document("hi", priority=200, roles=[role(rid="dup", display_name="Hi", permissions=())])
    compiled = SchemaCompiler().compile([lo, hi])
    assert compiled.roles["dup"].definition.display_name == "Hi"


def test_base_permissions_get_base_provenance():
    schema = SchemaCompiler().compile([_base()])
    for perm in ("courses.view_course", "courses.manage_tags"):
        prov = schema.role_permission_sources[("course_editor", perm)]
        assert [(rs.source.distribution, rs.origin_kind) for rs in prov] == [("test-dist", ORIGIN_BASE)]


def test_extension_grant_is_attributed_to_the_module_not_core():
    ext = make_document(
        "modx", priority=200, role_extensions=[extension("course_editor", add_permissions=("courses.export_course",))]
    )
    schema = SchemaCompiler().compile([_base(), ext])

    core = schema.role_permission_sources[("course_editor", "courses.view_course")]
    added = schema.role_permission_sources[("course_editor", "courses.export_course")]

    # Both permissions coexist on the role, but their origins remain distinct.
    assert [rs.origin_kind for rs in core] == [ORIGIN_BASE]
    assert [rs.origin_kind for rs in added] == [ORIGIN_EXTENSION]


def test_removed_permission_has_no_provenance():
    ext = make_document(
        "modx", priority=200, role_extensions=[extension("course_editor", remove_permissions=("courses.manage_tags",))]
    )
    schema = SchemaCompiler().compile([_base(), ext])
    assert ("course_editor", "courses.manage_tags") not in schema.role_permission_sources


class TestDiscardedContributionWarnings:
    """Priority silently picks a winner; the loser must be reported.

    ADR 0017 §4 requires warning about contributions that do not take effect
    because another file has a higher priority. A losing file is valid and was
    loaded, so without a warning it looks like it applied.
    """

    @staticmethod
    def _compile(*documents):
        return SchemaCompiler().compile(list(documents))

    def test_lower_priority_base_definition_warns(self, caplog):
        low = make_document("low", priority=100, roles=[role(rid="course_editor", display_name="Editor")])
        high = make_document("high", priority=200, roles=[role(rid="course_editor", display_name="Author")])

        with caplog.at_level(logging.WARNING):
            compiled = self._compile(high, low)

        assert compiled.roles["course_editor"].definition.display_name == "Author"
        assert "has no effect" in caplog.text
        assert make_source("low").source_id in caplog.text
        assert make_source("high").source_id in caplog.text

    def test_warning_names_both_priorities(self, caplog):
        low = make_document("low", priority=100, roles=[role(rid="course_editor", display_name="Editor")])
        high = make_document("high", priority=200, roles=[role(rid="course_editor", display_name="Author")])

        with caplog.at_level(logging.WARNING):
            self._compile(low, high)

        assert "priority 100" in caplog.text
        assert "priority 200" in caplog.text

    def test_warns_regardless_of_document_order(self, caplog):
        """Discovery order must not decide whether the operator is told."""
        low = make_document("low", priority=100, roles=[role(rid="course_editor", display_name="Editor")])
        high = make_document("high", priority=200, roles=[role(rid="course_editor", display_name="Author")])

        with caplog.at_level(logging.WARNING):
            self._compile(low, high)
        ascending = caplog.text
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            self._compile(high, low)

        assert "has no effect" in ascending
        assert "has no effect" in caplog.text

    def test_identical_duplicate_does_not_warn(self):
        """An identical definition merges sources; nothing is discarded."""
        first = make_document("first", priority=100, roles=[role(rid="course_editor")])
        second = make_document("second", priority=200, roles=[role(rid="course_editor")])

        compiled = self._compile(first, second)

        assert len(compiled.roles["course_editor"].sources) == 2

    def test_uses_singular_kind_label(self, caplog):
        """Messages say 'category', not the truncated attribute name."""
        low = make_document("low", priority=100, categories=[category("cat", display_name="Low")])
        high = make_document("high", priority=200, categories=[category("cat", display_name="High")])

        with caplog.at_level(logging.WARNING):
            self._compile(low, high)

        assert "category 'cat'" in caplog.text
        assert "categorie" not in caplog.text

    def test_conflict_error_uses_singular_kind_label(self):
        left = make_document("left", priority=100, categories=[category("cat", display_name="Left")])
        right = make_document("right", priority=100, categories=[category("cat", display_name="Right")])

        with pytest.raises(SchemaCompileError, match="Conflicting category definition"):
            self._compile(left, right)

    def test_losing_metadata_extension_warns(self, caplog):
        base = make_document("base", priority=100, roles=[role(rid="course_editor")])
        low = make_document("low", priority=100, role_extensions=[extension("course_editor", display_name="Low")])
        high = make_document("high", priority=200, role_extensions=[extension("course_editor", display_name="High")])

        with caplog.at_level(logging.WARNING):
            compiled = self._compile(base, low, high)

        assert compiled.roles["course_editor"].definition.display_name == "High"
        assert "role_extension display_name" in caplog.text
        assert make_source("low").source_id in caplog.text

    def test_losing_permission_extension_warns(self, caplog):
        base = make_document(
            "base",
            priority=100,
            permissions=[permission(cat="cat")],
            roles=[role(rid="course_editor", permissions=("courses.view_course",))],
        )
        low = make_document(
            "low",
            priority=100,
            role_extensions=[extension("course_editor", remove_permissions=("courses.view_course",))],
        )
        high = make_document(
            "high",
            priority=200,
            role_extensions=[extension("course_editor", add_permissions=("courses.view_course",))],
        )

        with caplog.at_level(logging.WARNING):
            compiled = self._compile(base, low, high)

        # The higher-priority add wins, so the permission stays.
        assert "courses.view_course" in compiled.roles["course_editor"].definition.permissions
        assert "role_extension remove of 'courses.view_course'" in caplog.text


class TestNoOpExtensionWarnings:
    """ADR 0023 §3: a no-op add/remove warns and leaves the result unchanged."""

    @staticmethod
    def _compile(*documents):
        return SchemaCompiler().compile(list(documents))

    def test_adding_an_existing_permission_warns(self, caplog):
        base = make_document(
            "base",
            priority=100,
            permissions=[permission(cat="cat")],
            roles=[role(rid="course_editor", permissions=("courses.view_course",))],
        )
        ext = make_document(
            "ext", priority=200, role_extensions=[extension("course_editor", add_permissions=("courses.view_course",))]
        )

        with caplog.at_level(logging.WARNING):
            compiled = self._compile(base, ext)

        assert compiled.roles["course_editor"].definition.permissions == ("courses.view_course",)
        assert "already on role" in caplog.text

    def test_removing_an_absent_permission_warns(self, caplog):
        base = make_document("base", priority=100, roles=[role(rid="course_editor", permissions=())])
        ext = make_document(
            "ext",
            priority=200,
            role_extensions=[extension("course_editor", remove_permissions=("courses.manage_tags",))],
        )

        with caplog.at_level(logging.WARNING):
            compiled = self._compile(base, ext)

        assert compiled.roles["course_editor"].definition.permissions == ()
        assert "not on role" in caplog.text


class TestDefensiveBranches:
    """Paths guarded against states validation is expected to have rejected."""

    def test_extension_for_an_unknown_role_is_skipped(self):
        """Validation errors on this; compilation must not raise on it."""
        ext = make_document(
            "ext", priority=200, role_extensions=[extension("ghost", add_permissions=("courses.view_course",))]
        )

        compiled = SchemaCompiler().compile([ext])

        assert not compiled.roles
        assert not compiled.role_permission_sources

    def test_identical_duplicate_categories_merge_sources(self):
        first = make_document("first", categories=[category("cat")])
        second = make_document("second", categories=[category("cat")])

        compiled = SchemaCompiler().compile([first, second])

        assert len(compiled.categories["cat"].sources) == 2

    def test_identical_duplicate_permissions_merge_sources(self):
        first = make_document("first", permissions=[permission(cat="cat")])
        second = make_document("second", permissions=[permission(cat="cat")])

        compiled = SchemaCompiler().compile([first, second])

        assert len(compiled.permissions["courses.view_course"].sources) == 2

    def test_lower_priority_base_definition_is_kept_out(self):
        """The 'keep existing' branch: a later, lower-priority file loses."""
        high = make_document("high", priority=200, roles=[role(rid="course_editor", display_name="Author")])
        low = make_document("low", priority=100, roles=[role(rid="course_editor", display_name="Editor")])

        compiled = SchemaCompiler().compile([high, low])

        assert compiled.roles["course_editor"].definition.display_name == "Author"
        assert [s.source_id for s in compiled.roles["course_editor"].sources] == [make_source("high").source_id]
