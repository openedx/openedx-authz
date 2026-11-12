"""Unit tests for openedx_authz.rest_api.utils."""

from datetime import datetime, timezone

from ddt import data, ddt, unpack
from django.test import TestCase

from openedx_authz.api.data import DefinitionKind
from openedx_authz.rest_api.data import AssignmentSortField, RoleSortField, SortOrder
from openedx_authz.rest_api.utils import filter_roles, sort_assignments, sort_roles


def _role(role: str, display_name: str, **fields) -> dict:
    """Build a role catalog entry with defaults for the fields a test does not care about."""
    return {
        "role": role,
        "display_name": display_name,
        "definition_kind": DefinitionKind.STATIC.value,
        "scope_types": ["lib"],
        "user_count": 0,
        "updated_at": None,
        **fields,
    }


EARLY = datetime(2026, 1, 1, tzinfo=timezone.utc)
LATE = datetime(2026, 6, 1, tzinfo=timezone.utc)
ROLES = [
    _role("library_user", "Library User", user_count=3),
    _role("course_staff", "course staff", scope_types=["course-v1"], user_count=10),
    _role("library_author", "Library Author", user_count=3),
    _role("custom_b", "Reviewer", definition_kind=DefinitionKind.USER_DEFINED.value, updated_at=EARLY),
    _role(
        "custom_a",
        "Grader",
        definition_kind=DefinitionKind.USER_DEFINED.value,
        scope_types=["course-v1", "lib"],
        updated_at=LATE,
    ),
]


@ddt
class TestFilterRoles(TestCase):
    """Tests for filter_roles."""

    @data(
        (None, None, ["library_user", "course_staff", "library_author", "custom_b", "custom_a"]),
        ("library", None, ["library_user", "library_author"]),
        # The search is case-insensitive and matches anywhere in the display name
        ("STAFF", None, ["course_staff"]),
        ("rary aut", None, ["library_author"]),
        ("nothing", None, []),
        (None, DefinitionKind.USER_DEFINED.value, ["custom_b", "custom_a"]),
        (None, DefinitionKind.STATIC.value, ["library_user", "course_staff", "library_author"]),
        ("er", DefinitionKind.USER_DEFINED.value, ["custom_b", "custom_a"]),
        ("library", DefinitionKind.USER_DEFINED.value, []),
    )
    @unpack
    def test_filters_and_preserves_order(self, search: str | None, definition_kind: str | None, expected: list[str]):
        """Roles matching both filters are kept in their original order."""
        result = filter_roles(ROLES, search, definition_kind)

        self.assertEqual([role["role"] for role in result], expected)

    def test_does_not_search_the_role_identifier(self):
        """The search matches the display name only, not the role identifier."""
        self.assertEqual(filter_roles(ROLES, "custom", None), [])


@ddt
class TestSortRoles(TestCase):
    """Tests for sort_roles."""

    @data(
        # Display names are compared case-insensitively
        (
            RoleSortField.DISPLAY_NAME,
            SortOrder.ASC,
            ["course_staff", "custom_a", "library_author", "library_user", "custom_b"],
        ),
        (
            RoleSortField.DISPLAY_NAME,
            SortOrder.DESC,
            ["custom_b", "library_user", "library_author", "custom_a", "course_staff"],
        ),
        # Ties ("lib") are broken by role identifier in both orders
        (
            RoleSortField.SCOPE_TYPE,
            SortOrder.ASC,
            ["course_staff", "custom_a", "custom_b", "library_author", "library_user"],
        ),
        (
            RoleSortField.SCOPE_TYPE,
            SortOrder.DESC,
            ["custom_b", "library_author", "library_user", "custom_a", "course_staff"],
        ),
        # Counts sort as numbers (10 > 3), ties by role identifier
        (
            RoleSortField.USER_COUNT,
            SortOrder.ASC,
            ["custom_a", "custom_b", "library_author", "library_user", "course_staff"],
        ),
        (
            RoleSortField.USER_COUNT,
            SortOrder.DESC,
            ["course_staff", "library_author", "library_user", "custom_a", "custom_b"],
        ),
        # Roles without updated_at go last in both orders
        (
            RoleSortField.UPDATED_AT,
            SortOrder.ASC,
            ["custom_b", "custom_a", "course_staff", "library_author", "library_user"],
        ),
        (
            RoleSortField.UPDATED_AT,
            SortOrder.DESC,
            ["custom_a", "custom_b", "course_staff", "library_author", "library_user"],
        ),
    )
    @unpack
    def test_sorts_by_field_and_order(self, sort_by: str, order: str, expected: list[str]):
        """Roles are sorted by the field, in the order, with stable tie-breaks."""
        result = sort_roles(ROLES, sort_by, order)

        self.assertEqual([role["role"] for role in result], expected)

    def test_defaults_to_display_name_ascending(self):
        """Without arguments, roles are sorted by display name, ascending."""
        self.assertEqual(sort_roles(ROLES), sort_roles(ROLES, RoleSortField.DISPLAY_NAME, SortOrder.ASC))

    def test_does_not_modify_the_input(self):
        """The input list keeps its order."""
        roles = list(ROLES)

        sort_roles(roles, RoleSortField.USER_COUNT, SortOrder.DESC)

        self.assertEqual(roles, ROLES)

    def test_empty_list(self):
        """No roles means nothing to sort."""
        self.assertEqual(sort_roles([]), [])

    @data(({"sort_by": "role"}, "Invalid field"), ({"order": "ascending"}, "Invalid order"))
    @unpack
    def test_invalid_arguments_raise_value_error(self, kwargs: dict, message: str):
        """An unknown sort field or order raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            sort_roles(ROLES, **kwargs)

        self.assertIn(message, str(ctx.exception))


class TestSortAssignments(TestCase):
    """Tests for sort_assignments."""

    def test_invalid_sort_field_raises_value_error(self):
        """Passing an unrecognised sort_by value raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            sort_assignments(assignments=[], sort_by="invalid_field")

        self.assertIn("invalid_field", str(ctx.exception))
        self.assertIn("Invalid field", str(ctx.exception))

    def test_invalid_sort_order_raises_value_error(self):
        """Passing an unrecognised order value raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            sort_assignments(assignments=[], sort_by=AssignmentSortField.ROLE, order="invalid_order")

        self.assertIn("invalid_order", str(ctx.exception))
        self.assertIn("Invalid order", str(ctx.exception))
