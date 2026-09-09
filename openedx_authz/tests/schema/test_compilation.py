"""Unit tests for the schema compilation step (merge + extensions + priority)."""

import pytest

from openedx_authz.engine.schema.compilation import SchemaCompiler
from openedx_authz.engine.schema.exceptions import SchemaCompileError
from openedx_authz.engine.schema.types import ORIGIN_BASE, ORIGIN_EXTENSION

from .factories import category, extension, make_document, permission, role

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
