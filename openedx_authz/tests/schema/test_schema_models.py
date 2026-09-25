"""Unit tests for the authz schema definition models (``openedx_authz.models.schema``).

These cover the model layer in isolation — the string representations, the
derived-identifier properties, and the ``origins_*`` query helpers — by writing
rows directly through the ORM. The applier that populates these tables from a
compiled schema is exercised separately.
"""

import pytest

from openedx_authz.constants import SchemaOriginKind
from openedx_authz.models.schema import (
    AuthzCategorySource,
    AuthzPermissionCategory,
    AuthzPermissionDefinition,
    AuthzPermissionSource,
    AuthzRoleDefinition,
    AuthzRolePermission,
    AuthzRolePermissionSource,
    AuthzRoleSource,
    AuthzSchemaSource,
    OriginKind,
    origin_for_role_permission,
    origins_for_category,
    origins_for_permission,
    origins_for_role,
)

pytestmark = pytest.mark.django_db


def _source(distribution="openedx-authz", module="openedx_authz.authz"):
    return AuthzSchemaSource.objects.create(distribution=distribution, module=module)


def _permission(namespace="courses", name="view_course", category=None):
    return AuthzPermissionDefinition.objects.create(
        namespace=namespace,
        name=name,
        display_name=name.replace("_", " ").title(),
        category=category,
    )


class TestOriginKind:
    """OriginKind mirrors the Django-free SchemaOriginKind constant."""

    def test_values_match_the_shared_constant(self):
        """The Django enum values mirror the Django-free ``SchemaOriginKind``."""
        assert OriginKind.BASE.value == SchemaOriginKind.BASE.value
        assert OriginKind.EXTENSION.value == SchemaOriginKind.EXTENSION.value

    def test_labels_are_human_readable(self):
        """Each origin kind exposes a human-readable label."""
        assert OriginKind.BASE.label == "Base"
        assert OriginKind.EXTENSION.label == "Extension"


class TestStringRepresentations:
    """Every model's ``__str__`` and derived-id property."""

    def test_source_id_replaces_dots_with_slashes(self):
        """A source's id renders the dotted module as a slash path."""
        source = _source(module="openedx_authz.authz")
        assert source.source_id == "openedx-authz:openedx_authz/authz"
        assert str(source) == "openedx-authz:openedx_authz/authz"

    def test_category_str_is_its_id(self):
        """A category stringifies to its stable id."""
        category = AuthzPermissionCategory.objects.create(category_id="content", display_name="Content")
        assert str(category) == "content"

    def test_permission_identifier_is_namespace_dot_name(self):
        """A permission's identifier and str are its ``namespace.name``."""
        permission = _permission(namespace="courses", name="view_course")
        assert permission.identifier == "courses.view_course"
        assert str(permission) == "courses.view_course"

    def test_role_str_is_its_id(self):
        """A role stringifies to its stable role id."""
        role = AuthzRoleDefinition.objects.create(role_id="course_editor", display_name="Course Editor")
        assert str(role) == "course_editor"

    def test_role_permission_str_traverses_to_stable_identifiers(self):
        """A grant stringifies as ``role -> permission @ scope`` using stable ids."""
        role = AuthzRoleDefinition.objects.create(role_id="course_editor", display_name="Course Editor")
        permission = _permission()
        grant = AuthzRolePermission.objects.create(role=role, permission=permission, scope="course-v1")
        assert str(grant) == "course_editor -> courses.view_course @ course-v1"


class TestOriginHelpers:
    """The four ``origins_*`` query helpers resolve contributing distributions."""

    def test_origins_for_role_returns_sorted_distinct_distributions(self):
        """``origins_for_role`` returns each contributing distribution once, sorted."""
        role = AuthzRoleDefinition.objects.create(role_id="course_editor", display_name="Course Editor")
        core = _source(distribution="openedx-authz")
        plugin = _source(distribution="my-plugin", module="my_plugin.authz")
        # Two sources, added out of order, to prove sorting and distinctness.
        AuthzRoleSource.objects.create(role=role, source=plugin, origin_kind=OriginKind.EXTENSION)
        AuthzRoleSource.objects.create(role=role, source=core, origin_kind=OriginKind.BASE)
        assert origins_for_role("course_editor") == ["my-plugin", "openedx-authz"]

    def test_origins_for_role_empty_when_unknown(self):
        """``origins_for_role`` returns an empty list for an unknown role."""
        assert origins_for_role("does_not_exist") == []

    def test_origins_for_permission_matches_by_complete_id(self):
        """``origins_for_permission`` matches on the full ``namespace.name`` id."""
        permission = _permission(namespace="courses", name="view_course")
        source = _source()
        AuthzPermissionSource.objects.create(permission=permission, source=source)
        assert origins_for_permission("courses.view_course") == ["openedx-authz"]
        # A different namespace with the same name must not match.
        assert origins_for_permission("libraries.view_course") == []

    def test_origins_for_category_matches_by_id(self):
        """``origins_for_category`` matches on the category id."""
        category = AuthzPermissionCategory.objects.create(category_id="content", display_name="Content")
        source = _source()
        AuthzCategorySource.objects.create(category=category, source=source)
        assert origins_for_category("content") == ["openedx-authz"]
        assert origins_for_category("missing") == []

    def test_origin_for_role_permission_isolates_one_grant(self):
        """``origin_for_role_permission`` reports sources for one grant, not sibling grants."""
        role = AuthzRoleDefinition.objects.create(role_id="course_editor", display_name="Course Editor")
        granted = _permission(namespace="courses", name="view_course")
        other = _permission(namespace="courses", name="edit_course_content")
        core = _source(distribution="openedx-authz")
        plugin = _source(distribution="my-plugin", module="my_plugin.authz")

        granted_row = AuthzRolePermission.objects.create(role=role, permission=granted, scope="course-v1")
        other_row = AuthzRolePermission.objects.create(role=role, permission=other, scope="course-v1")
        # The queried grant is contributed by both distributions; the other by core only.
        AuthzRolePermissionSource.objects.create(role_permission=granted_row, source=core, origin_kind=OriginKind.BASE)
        AuthzRolePermissionSource.objects.create(
            role_permission=granted_row, source=plugin, origin_kind=OriginKind.EXTENSION
        )
        AuthzRolePermissionSource.objects.create(role_permission=other_row, source=core, origin_kind=OriginKind.BASE)

        assert origin_for_role_permission("course_editor", "courses.view_course") == ["my-plugin", "openedx-authz"]
        # The same role, a different permission, is not swept in.
        assert origin_for_role_permission("course_editor", "courses.edit_course_content") == ["openedx-authz"]
