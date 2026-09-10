"""Unit tests for schema type helpers."""

from openedx_authz.engine.schema.types import (
    CompiledDefinition,
    CompiledSchema,
    PermissionDefinition,
    RoleDefinition,
    SourceRecord,
)


def test_source_id_combines_distribution_and_module_path():
    source = SourceRecord(
        distribution="openedx-authz",
        distribution_version="1.0",
        module="openedx_authz.authz",
        resource_path="course_roles.authz.yaml",
        schema_version="1.0",
        content_digest="abc",
    )
    assert source.source_id == "openedx-authz:openedx_authz/authz/course_roles.authz.yaml"


def test_permission_identifier_joins_namespace_and_name():
    perm = PermissionDefinition(
        namespace="courses",
        name="view_course",
        display_name="View",
        description="d",
        category="cat",
        scopes=("course-v1",),
    )
    assert perm.identifier == "courses.view_course"


def test_role_permission_pairs_are_sorted_and_flattened():
    role = RoleDefinition(
        id="course_admin",
        display_name="Admin",
        description="d",
        scopes=("course-v1",),
        permissions=("courses.view_course", "courses.edit_course_content"),
    )
    schema = CompiledSchema(
        roles={"course_admin": CompiledDefinition("role", "course_admin", role, ())}
    )
    assert schema.role_permission_pairs() == [
        ("course_admin", "courses.edit_course_content"),
        ("course_admin", "courses.view_course"),
    ]
