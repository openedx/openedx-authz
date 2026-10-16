"""Unit tests for the schema compilation step (merge + extensions + priority).

Grouped by concern: base compilation, extensions, priority resolution,
provenance, discarded-contribution warnings, no-op extension warnings, and the
defensive branches guarding states validation is expected to have rejected.
"""

import logging
from dataclasses import fields

import pytest

from openedx_authz.constants import SchemaOriginKind
from openedx_authz.engine.schema.compilation import RoleMetadataField, SchemaCompiler
from openedx_authz.engine.schema.exceptions import SchemaCompileError
from openedx_authz.engine.schema.types import RoleExtension

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


class TestRoleMetadataFieldInvariant:
    """``RoleMetadataField`` must stay in lockstep with ``RoleExtension``.

    ``_gather_extension_changes`` reads each member via ``getattr`` with no
    default, so a member naming a field that ``RoleExtension`` does not declare
    would raise at compile time. This guards that coupling at the enum level,
    turning a rename drift into a fast, obvious test failure.
    """

    def test_every_member_is_a_role_extension_field(self):
        """Each enum value names a real ``RoleExtension`` field."""
        extension_fields = {f.name for f in fields(RoleExtension)}
        enum_values = {member.value for member in RoleMetadataField}
        assert enum_values <= extension_fields

    def test_members_exclude_non_metadata_fields(self):
        """Permission and identity fields are not metadata an extension replaces."""
        enum_values = {member.value for member in RoleMetadataField}
        assert enum_values.isdisjoint({"role_id", "add_permissions", "remove_permissions"})


class TestBaseCompilation:
    """Compiling base definitions with no extensions applied."""

    def test_base_definitions_compile(self):
        """A single base document yields its roles and permissions verbatim."""
        schema = SchemaCompiler().compile([_base()])
        assert set(schema.roles) == {"course_editor"}
        assert len(schema.permissions) == 3
        # Base definitions keep their declared order; rendering sorts later.
        assert schema.roles["course_editor"].definition.permissions == (
            "courses.view_course",
            "courses.manage_tags",
        )


class TestExtensions:
    """Applying ``role_extensions`` on top of a base role definition."""

    def test_extension_adds_and_removes_permissions_and_metadata(self):
        """One extension can add, remove, rename, and hide in a single pass."""
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

    def test_extension_sources_are_retained(self):
        """A role touched by an extension keeps both the base and extension sources."""
        ext = make_document("ext", priority=200, role_extensions=[extension("course_editor", display_name="X")])
        compiled = SchemaCompiler().compile([_base(), ext])
        assert len(compiled.roles["course_editor"].sources) == 2


class TestPriorityResolution:
    """How priority resolves conflicting role-extension contributions (higher wins; ties fail).

    Priority applies to role extensions only; base-definition conflicts are
    covered by :class:`TestBaseDefinitionConflicts` (ADR 0031).
    """

    def test_equal_priority_metadata_conflict_raises(self):
        """Two extensions setting the same field at equal priority is an error."""
        a = make_document("a", priority=200, role_extensions=[extension("course_editor", display_name="A")])
        b = make_document("b", priority=200, role_extensions=[extension("course_editor", display_name="B")])
        with pytest.raises(SchemaCompileError):
            SchemaCompiler().compile([_base(), a, b])

    def test_higher_priority_metadata_wins(self):
        """The higher-priority extension's metadata value takes effect."""
        lo = make_document("lo", priority=150, role_extensions=[extension("course_editor", display_name="Lo")])
        hi = make_document("hi", priority=300, role_extensions=[extension("course_editor", display_name="Hi")])
        definition = SchemaCompiler().compile([_base(), lo, hi]).roles["course_editor"].definition
        assert definition.display_name == "Hi"

    def test_equal_priority_add_remove_conflict_raises(self):
        """An add and a remove of the same permission at equal priority is an error."""
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


class TestBaseDefinitionConflicts:
    """Priority does not resolve conflicting base definitions (ADR 0031).

    A base definition (category, permission, or role) is a single source of
    truth. Two files that declare the same identifier differently are an
    unresolvable conflict regardless of priority; only identical declarations
    merge. Contrast with :class:`TestPriorityResolution`, where priority does
    pick a winner among role extensions.
    """

    def test_conflicting_base_definition_equal_priority_raises(self):
        """Two differing base definitions at equal priority is an error."""
        a = make_document("a", priority=100, roles=[role(rid="dup", display_name="A", permissions=())])
        b = make_document("b", priority=100, roles=[role(rid="dup", display_name="B", permissions=())])
        with pytest.raises(SchemaCompileError, match="Conflicting role definition"):
            SchemaCompiler().compile([a, b])

    def test_higher_priority_does_not_win_for_base_definitions(self):
        """A higher-priority base definition does not replace a lower-priority one.

        Unlike role extensions, the disagreement is an unresolvable conflict and
        raises regardless of priority.
        """
        lo = make_document("lo", priority=100, roles=[role(rid="dup", display_name="Lo", permissions=())])
        hi = make_document("hi", priority=200, roles=[role(rid="dup", display_name="Hi", permissions=())])
        with pytest.raises(SchemaCompileError):
            SchemaCompiler().compile([lo, hi])

    def test_base_definition_conflict_raises_regardless_of_order(self):
        """Discovery order must not change the outcome; both orders raise."""
        lo = make_document("lo", priority=100, roles=[role(rid="dup", display_name="Lo", permissions=())])
        hi = make_document("hi", priority=200, roles=[role(rid="dup", display_name="Hi", permissions=())])
        with pytest.raises(SchemaCompileError):
            SchemaCompiler().compile([lo, hi])
        with pytest.raises(SchemaCompileError):
            SchemaCompiler().compile([hi, lo])

    def test_error_mentions_priority_does_not_apply(self):
        """The conflict error points the author to role_extensions (ADR 0031)."""
        lo = make_document("lo", priority=100, categories=[category("cat", display_name="Lo")])
        hi = make_document("hi", priority=200, categories=[category("cat", display_name="Hi")])
        with pytest.raises(SchemaCompileError, match="Priority does not resolve base definitions"):
            SchemaCompiler().compile([lo, hi])

    def test_identical_base_definitions_merge_regardless_of_priority(self):
        """Identical declarations are not a conflict; their sources merge."""
        first = make_document("first", priority=100, roles=[role(rid="dup", permissions=())])
        second = make_document("second", priority=200, roles=[role(rid="dup", permissions=())])
        compiled = SchemaCompiler().compile([first, second])
        assert len(compiled.roles["dup"].sources) == 2


class TestProvenance:
    """Each role-permission grant records where it came from (ADR 0025)."""

    def test_base_permissions_get_base_provenance(self):
        """Permissions from the role's own definition are tagged ``BASE``."""
        schema = SchemaCompiler().compile([_base()])
        for perm in ("courses.view_course", "courses.manage_tags"):
            prov = schema.role_permission_sources[("course_editor", perm)]
            assert [(rs.source.distribution, rs.origin_kind) for rs in prov] == [("test-dist", SchemaOriginKind.BASE)]

    def test_extension_grant_is_attributed_to_the_module_not_core(self):
        """An extension-added grant is tagged ``EXTENSION``, base grants stay ``BASE``."""
        ext = make_document(
            "modx",
            priority=200,
            role_extensions=[extension("course_editor", add_permissions=("courses.export_course",))],
        )
        schema = SchemaCompiler().compile([_base(), ext])

        core = schema.role_permission_sources[("course_editor", "courses.view_course")]
        added = schema.role_permission_sources[("course_editor", "courses.export_course")]

        # Both permissions coexist on the role, but their origins remain distinct.
        assert [rs.origin_kind for rs in core] == [SchemaOriginKind.BASE]
        assert [rs.origin_kind for rs in added] == [SchemaOriginKind.EXTENSION]

    def test_removed_permission_has_no_provenance(self):
        """A permission removed by an extension leaves no provenance entry."""
        ext = make_document(
            "modx",
            priority=200,
            role_extensions=[extension("course_editor", remove_permissions=("courses.manage_tags",))],
        )
        schema = SchemaCompiler().compile([_base(), ext])
        assert ("course_editor", "courses.manage_tags") not in schema.role_permission_sources


class TestDiscardedContributionWarnings:
    """Priority silently picks a winner among role extensions; the loser must be reported.

    ADR 0017 §4 requires warning about extension contributions that do not take
    effect because another file has a higher priority. A losing file is valid
    and was loaded, so without a warning it looks like it applied. Priority does
    not resolve base definitions (ADR 0031), so a losing base definition is not
    a case here; conflicting base definitions raise instead (see
    :class:`TestBaseDefinitionConflicts`).
    """

    @staticmethod
    def _compile(*documents):
        return SchemaCompiler().compile(list(documents))

    def test_identical_duplicate_does_not_warn(self):
        """An identical definition merges sources; nothing is discarded."""
        first = make_document("first", priority=100, roles=[role(rid="course_editor")])
        second = make_document("second", priority=200, roles=[role(rid="course_editor")])

        compiled = self._compile(first, second)

        assert len(compiled.roles["course_editor"].sources) == 2

    def test_conflict_error_uses_singular_kind_label(self):
        """A conflict error uses the singular kind label ('category')."""
        left = make_document("left", priority=100, categories=[category("cat", display_name="Left")])
        right = make_document("right", priority=100, categories=[category("cat", display_name="Right")])

        with pytest.raises(SchemaCompileError, match="Conflicting category definition"):
            self._compile(left, right)

    def test_losing_metadata_extension_warns(self, caplog):
        """A metadata extension that loses on priority is reported, naming its source."""
        base = make_document("base", priority=100, roles=[role(rid="course_editor")])
        low = make_document("low", priority=100, role_extensions=[extension("course_editor", display_name="Low")])
        high = make_document("high", priority=200, role_extensions=[extension("course_editor", display_name="High")])

        with caplog.at_level(logging.WARNING):
            compiled = self._compile(base, low, high)

        assert compiled.roles["course_editor"].definition.display_name == "High"
        assert "role_extension display_name" in caplog.text
        assert make_source("low").source_id in caplog.text

    def test_losing_permission_extension_warns(self, caplog):
        """A permission-changing extension that loses on priority is reported."""
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
        """Adding a permission the role already has warns and is a no-op."""
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
        """Removing a permission the role does not have warns and is a no-op."""
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
        """Two identical category definitions merge into one, keeping both sources."""
        first = make_document("first", categories=[category("cat")])
        second = make_document("second", categories=[category("cat")])

        compiled = SchemaCompiler().compile([first, second])

        assert len(compiled.categories["cat"].sources) == 2

    def test_identical_duplicate_permissions_merge_sources(self):
        """Two identical permission definitions merge into one, keeping both sources."""
        first = make_document("first", permissions=[permission(cat="cat")])
        second = make_document("second", permissions=[permission(cat="cat")])

        compiled = SchemaCompiler().compile([first, second])

        assert len(compiled.permissions["courses.view_course"].sources) == 2

    def test_differing_base_definition_raises_even_though_validation_guards_it(self):
        """Validation errors on this first; compilation must still raise, not pick a winner.

        Priority does not resolve base definitions (ADR 0031), so a direct call
        to the compiler with two differing base definitions is a conflict.
        """
        high = make_document("high", priority=200, roles=[role(rid="course_editor", display_name="Author")])
        low = make_document("low", priority=100, roles=[role(rid="course_editor", display_name="Editor")])

        with pytest.raises(SchemaCompileError):
            SchemaCompiler().compile([high, low])
