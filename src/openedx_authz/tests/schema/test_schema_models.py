"""Unit tests for the authz schema definition models (``openedx_authz.models.schema``).

These cover the model layer in isolation — the string representations, the
derived-identifier properties, and the ``origins_*`` query helpers — by writing
rows directly through the ORM. The applier that populates these tables from a
compiled schema is exercised separately.
"""

import pytest
from django.utils import timezone

from openedx_authz.constants import DefinitionKind, SchemaOriginKind
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
    RoleDefinitionKind,
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


class TestRoleDefinitionKindChoices:
    """RoleDefinitionKind exposes human-readable labels."""

    def test_labels_are_human_readable(self):
        """Each definition kind exposes a human-readable label."""
        assert RoleDefinitionKind.STATIC.label == "Static"
        assert RoleDefinitionKind.USER_DEFINED.label == "User defined"


class TestPermissionWithIdentifiers:
    """``with_identifiers`` finds permissions by their complete ``namespace.name`` ID."""

    def test_returns_only_the_requested_permissions(self):
        """Each complete ID matches its own namespace and name, not a mix of both."""
        view_course = _permission("courses", "view_course")
        view_library = _permission("content_libraries", "view_library")
        _permission("courses", "view_library")

        found = AuthzPermissionDefinition.objects.with_identifiers(
            ["courses.view_course", "content_libraries.view_library"]
        )

        assert set(found) == {view_course, view_library}

    def test_unknown_identifiers_match_nothing(self):
        """An ID with no stored permission is ignored."""
        _permission("courses", "view_course")

        assert not AuthzPermissionDefinition.objects.with_identifiers(["courses.missing"]).exists()

    def test_no_identifiers_match_nothing(self):
        """An empty list returns an empty queryset instead of every permission."""
        _permission("courses", "view_course")

        assert not AuthzPermissionDefinition.objects.with_identifiers([]).exists()

    def test_repeated_identifiers_return_each_permission_once(self):
        """A repeated ID is accepted and its permission is returned a single time."""
        view_course = _permission("courses", "view_course")

        found = AuthzPermissionDefinition.objects.with_identifiers(["courses.view_course", "courses.view_course"])

        assert list(found) == [view_course]


class TestRoleGrantsInScopeTypes:
    """``with_grants_in_scope_types`` filters roles and ``prefetch_grants_in_scope_types`` loads their grants."""

    def test_filter_matches_roles_with_any_grant_in_the_scope_types(self):
        """A role whose only grant is hidden still counts, a role granting elsewhere does not."""
        hidden_permission = AuthzPermissionDefinition.objects.create(
            namespace="courses", name="manage_advanced", display_name="Manage Advanced", hidden=True
        )
        hidden_only = AuthzRoleDefinition.objects.create(role_id="course_hidden_only", display_name="Hidden Only")
        library_only = AuthzRoleDefinition.objects.create(role_id="library_editor", display_name="Library Editor")
        AuthzRoleDefinition.objects.create(role_id="course_reviewer", display_name="Reviewer")
        AuthzRolePermission.objects.create(role=hidden_only, permission=hidden_permission, scope="course-v1")
        AuthzRolePermission.objects.create(role=library_only, permission=_permission(), scope="lib")

        found = AuthzRoleDefinition.objects.with_grants_in_scope_types(["course-v1"])

        assert list(found) == [hidden_only]

    def test_filter_returns_each_role_once(self):
        """A role with several grants in the scope types is returned a single time."""
        role = AuthzRoleDefinition.objects.create(role_id="course_editor", display_name="Course Editor")
        AuthzRolePermission.objects.create(role=role, permission=_permission(name="view_course"), scope="course-v1")
        AuthzRolePermission.objects.create(role=role, permission=_permission(name="edit_course"), scope="course-v1")

        assert list(AuthzRoleDefinition.objects.with_grants_in_scope_types(["course-v1"])) == [role]

    def test_prefetch_loads_only_visible_grants_in_the_scope_types(self):
        """Hidden grants and grants in other scope types are left out of ``grants``."""
        hidden_category = AuthzPermissionCategory.objects.create(
            category_id="hidden", display_name="Hidden", hidden=True
        )
        role = AuthzRoleDefinition.objects.create(role_id="course_editor", display_name="Course Editor")
        shown = AuthzRolePermission.objects.create(
            role=role, permission=_permission(name="view_course"), scope="course-v1"
        )
        AuthzRolePermission.objects.create(
            role=role, permission=_permission(name="edit_course", category=hidden_category), scope="course-v1"
        )
        AuthzRolePermission.objects.create(role=role, permission=_permission(name="view_library"), scope="lib")

        (loaded,) = AuthzRoleDefinition.objects.prefetch_grants_in_scope_types(["course-v1"])

        assert loaded.grants == [shown]

    def test_prefetch_does_not_filter_roles(self):
        """A role without grants in the scope types is kept, with empty ``grants``."""
        role = AuthzRoleDefinition.objects.create(role_id="course_reviewer", display_name="Reviewer")

        (loaded,) = AuthzRoleDefinition.objects.prefetch_grants_in_scope_types(["course-v1"])

        assert loaded == role
        assert loaded.grants == []


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


class TestRoleDefinitionKind:
    """Querysets that keep static and custom roles apart (ADR 0035)."""

    @staticmethod
    def _create_role(role_id: str, **kwargs: object) -> AuthzRoleDefinition:
        """Create a role definition with its id as display name."""
        return AuthzRoleDefinition.objects.create(role_id=role_id, display_name=role_id, **kwargs)

    def test_new_roles_are_static_and_not_removed(self):
        """A role created without a kind is a static role that has not been removed."""
        role = self._create_role("course_editor")

        assert role.definition_kind == DefinitionKind.STATIC.value
        assert role.removed_at is None

    def test_querysets_split_roles_by_kind(self):
        """``static``, ``user_defined`` and ``active`` partition the roles as expected."""
        static = self._create_role("course_editor")
        active = self._create_role("custom_active", definition_kind=DefinitionKind.USER_DEFINED.value)
        removed = self._create_role(
            "custom_removed", definition_kind=DefinitionKind.USER_DEFINED.value, removed_at=timezone.now()
        )

        assert list(AuthzRoleDefinition.objects.static()) == [static]
        assert set(AuthzRoleDefinition.objects.user_defined()) == {active, removed}
        assert set(AuthzRoleDefinition.objects.active()) == {static, active}

    def test_visible_excludes_hidden_and_removed_roles(self):
        """``visible`` leaves out hidden roles and removed custom roles."""
        shown = self._create_role("course_editor")
        self._create_role("legacy_role", hidden=True)
        self._create_role(
            "custom_removed", definition_kind=DefinitionKind.USER_DEFINED.value, removed_at=timezone.now()
        )

        assert list(AuthzRoleDefinition.objects.visible()) == [shown]

    def test_grants_split_by_the_kind_of_their_role(self):
        """The grant querysets follow the kind of the role that owns each grant."""
        permission = _permission()
        static = self._create_role("course_editor")
        custom = self._create_role("custom_designer", definition_kind=DefinitionKind.USER_DEFINED.value)
        static_grant = AuthzRolePermission.objects.create(role=static, permission=permission, scope="course-v1")
        custom_grant = AuthzRolePermission.objects.create(role=custom, permission=permission, scope="course-v1")

        assert list(AuthzRolePermission.objects.static()) == [static_grant]
        assert list(AuthzRolePermission.objects.user_defined()) == [custom_grant]


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
