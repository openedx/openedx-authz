"""Unit tests for openedx_authz.rest_api.utils.

The three-tier cascade (course override, else org override, else platform
default) is edx-platform's ``CourseWaffleFlag.is_enabled()``, not
importable in this repo's standalone test suite. ``CourseWaffleFlagMock``
below stands in for it, so ``test_course_scope_follows_the_adr_0015_truth_table``
can still exercise every row of the ADR 0015 truth table end to end.

There is no edx-platform API to check the flag for an org alone (see
issue #360), so ``is_scope_visible`` simulates the org-tier step
``CourseWaffleFlag.is_enabled()`` runs internally for an org-glob scope,
using the same ``WaffleFlagOrgOverrideModel`` building block, mocked here
for the same reason: it isn't importable in this repo's standalone suite.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from ddt import data, ddt, unpack
from django.test import TestCase

from openedx_authz.api.data import (
    ContentLibraryData,
    CourseOverviewData,
    OrgCourseOverviewGlobData,
    PlatformCourseOverviewGlobData,
)
from openedx_authz.rest_api.data import AssignmentSortField
from openedx_authz.rest_api.utils import has_visible_scope, is_scope_visible, sort_assignments

COURSE_SCOPE = "course-v1:Org1+COURSE1+2024"
OTHER_COURSE_SCOPE = "course-v1:Org1+COURSE2+2024"
LIB_SCOPE = "lib:Org1:LIB1"
ORG_GLOB_COURSE_SCOPE = OrgCourseOverviewGlobData.build_external_key("Org1")
PLATFORM_GLOB_COURSE_SCOPE = PlatformCourseOverviewGlobData.build_external_key()
FLAG_NAME = "authz.enable_course_authoring"

class CourseWaffleFlagMock:
    """Stand-in for edx-platform's ``CourseWaffleFlag``, not importable in this repo's standalone suite.

    Callable with an optional course key, matching ``enable_authz_course_authoring``'s
    signature, so it can be patched in directly. Replicates the real
    cascade: course override, else org override, else platform default.
    """

    def __init__(self, platform: bool, org_override: bool | None = None, course_override: bool | None = None):
        self.platform = platform
        self.org_override = org_override
        self.course_override = course_override

    def __call__(self, course_key=None) -> bool:
        if self.course_override is not None:
            return self.course_override
        if self.org_override is not None:
            return self.org_override
        return self.platform


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


@ddt
class TestIsScopeVisible(TestCase):
    """Test is_scope_visible, dispatching to the right override tier depending on the scope's type."""

    def setUp(self):
        self.course_scope = CourseOverviewData(external_key=COURSE_SCOPE)

    @data(
        # (platform, org_override, course_override, expected) - ADR 0015 truth table, override combinations only.
        # Permission isn't this function's concern, so staff/action rows are covered end to end in test_views.py.
        (False, None, None, False),
        (True, None, None, True),
        (False, True, None, True),
        (True, True, None, True),
        (False, False, None, False),
        (True, False, None, False),
        (False, None, True, True),
        (True, None, True, True),
        (False, None, False, False),
        (True, None, False, False),
        (True, True, False, False),  # course override wins even when the org override disagrees.
        (False, False, True, True),  # course override wins even when the org override disagrees.
    )
    @unpack
    def test_course_scope_follows_the_adr_0015_truth_table(
        self, platform: bool, org_override: bool | None, course_override: bool | None, expected: bool
    ):
        """Test is_scope_visible for a concrete course scope against every override combination.

        Expected result:
            - The scope is visible exactly when the ADR 0015 truth table says so:
              course override wins, else org override, else platform default.
        """
        with patch(
            "openedx_authz.rest_api.utils.enable_authz_course_authoring",
            CourseWaffleFlagMock(platform, org_override, course_override),
        ):
            self.assertEqual(is_scope_visible(self.course_scope), expected)

    def test_course_flag_off_for_one_course_does_not_affect_a_different_course(self):
        """Test is_scope_visible for two different course scopes under the same flag.

        Expected result:
            - A course-level override for one course does not leak to another course.
        """

        def flag_side_effect(course_key):
            return str(course_key) != COURSE_SCOPE

        with patch(
            "openedx_authz.rest_api.utils.enable_authz_course_authoring",
            side_effect=flag_side_effect,
        ):
            self.assertFalse(is_scope_visible(CourseOverviewData(external_key=COURSE_SCOPE)))
            self.assertTrue(is_scope_visible(CourseOverviewData(external_key=OTHER_COURSE_SCOPE)))

    def _mock_org_model(self, override_choice: str):
        mock_org_model = MagicMock()
        mock_org_model.ALL_CHOICES = SimpleNamespace(on="on", off="off", unset="unset")
        mock_org_model.override_value.return_value = override_choice
        return mock_org_model

    @data(
        ("on", False, True),  # org override forces on, even though the platform default is off.
        ("off", True, False),  # org override forces off, even though the platform default is on.
        ("unset", True, True),  # no org override, falls back to the platform default.
        ("unset", False, False),  # no org override, platform default is off too.
    )
    @unpack
    def test_org_glob_scope_org_override_takes_precedence_over_platform_default(
        self, override_choice: str, platform_default: bool, expected: bool
    ):
        """Test is_scope_visible for an org-glob scope against every org/platform combination.

        Expected result:
            - The scope follows the org override when set, else the platform default.
        """
        scope = OrgCourseOverviewGlobData(external_key=ORG_GLOB_COURSE_SCOPE)
        with patch(
            "openedx_authz.rest_api.utils.WaffleFlagOrgOverrideModel",
            self._mock_org_model(override_choice),
        ), patch(
            "openedx_authz.rest_api.utils.AUTHZ_COURSE_AUTHORING_FLAG", SimpleNamespace(name=FLAG_NAME)
        ), patch(
            "openedx_authz.rest_api.utils.enable_authz_course_authoring", return_value=platform_default
        ):
            self.assertEqual(is_scope_visible(scope), expected)

    @data(True, False)
    def test_platform_glob_scope_follows_the_platform_tier(self, platform_enabled: bool):
        """Test is_scope_visible for a platform-glob scope.

        Expected result:
            - The scope has no course or org, so it follows the platform tier only.
        """
        scope = PlatformCourseOverviewGlobData(external_key=PLATFORM_GLOB_COURSE_SCOPE)
        with patch(
            "openedx_authz.rest_api.utils.enable_authz_course_authoring",
            return_value=platform_enabled,
        ) as mock_enabled:
            self.assertEqual(is_scope_visible(scope), platform_enabled)
            mock_enabled.assert_called_once_with()

    @data(True, False)
    def test_library_scope_is_always_visible_regardless_of_the_flag(self, flag_enabled: bool):
        """Test is_scope_visible for a library scope, regardless of the flag's state.

        Expected result:
            - The scope is always visible, since it isn't course-authoring-gated.
        """
        with patch(
            "openedx_authz.rest_api.utils.enable_authz_course_authoring",
            return_value=flag_enabled,
        ):
            self.assertTrue(is_scope_visible(ContentLibraryData(external_key=LIB_SCOPE)))


@ddt
class TestHasVisibleScope(TestCase):
    """Test has_visible_scope, which resolves scope_value (course/library/org-glob/None) and dispatches.

    The flag's effective state doesn't depend on who's asking, so there is
    no staff/superuser special case here: staff bypass Casbin only for the
    permission check (is_user_allowed_in_scope), not this one.
    """

    ACTION = "courses.view_course"
    USERNAME = "someuser"

    @data(True, False)
    def test_course_scope_follows_the_flag(self, flag_enabled: bool):
        """Test has_visible_scope with a given course scope.

        Expected result:
            - The result matches is_scope_visible's course-tier result for that scope.
        """
        with patch(
            "openedx_authz.rest_api.utils.enable_authz_course_authoring", return_value=flag_enabled
        ):
            self.assertEqual(has_visible_scope(self.USERNAME, self.ACTION, COURSE_SCOPE), flag_enabled)

    @data(True, False)
    def test_library_scope_is_always_visible(self, flag_enabled: bool):
        """Test has_visible_scope with a given library scope, regardless of the flag's state.

        Expected result:
            - The scope is always visible.
        """
        with patch(
            "openedx_authz.rest_api.utils.enable_authz_course_authoring", return_value=flag_enabled
        ):
            self.assertTrue(has_visible_scope(self.USERNAME, self.ACTION, LIB_SCOPE))

    def test_any_scope_check_is_allowed_when_a_granted_scope_is_visible(self):
        """Test has_visible_scope with no scope given, and a mix of granted scopes.

        Expected result:
            - Visible if at least one of the user's granted scopes is visible.
        """
        with patch(
            "openedx_authz.rest_api.utils.get_scopes_for_user_and_permission",
            return_value=[
                CourseOverviewData(external_key=COURSE_SCOPE),
                ContentLibraryData(external_key=LIB_SCOPE),
            ],
        ), patch("openedx_authz.rest_api.utils.enable_authz_course_authoring", return_value=False):
            # The course scope is flag-disabled, but the library scope always counts, so overall visible.
            self.assertTrue(has_visible_scope(self.USERNAME, self.ACTION, None))

    def test_any_scope_check_is_denied_when_no_granted_scope_is_visible(self):
        """Test has_visible_scope with no scope given, and only flag-disabled granted scopes.

        Expected result:
            - Not visible, since none of the user's granted scopes are visible.
        """
        with patch(
            "openedx_authz.rest_api.utils.get_scopes_for_user_and_permission",
            return_value=[CourseOverviewData(external_key=COURSE_SCOPE)],
        ), patch("openedx_authz.rest_api.utils.enable_authz_course_authoring", return_value=False):
            self.assertFalse(has_visible_scope(self.USERNAME, self.ACTION, None))

    def test_any_scope_check_is_denied_when_user_has_no_granted_scopes(self):
        """Test has_visible_scope with no scope given, and no granted scopes at all.

        Expected result:
            - Not visible. A staff/superuser with no explicit Casbin grants gets the
              same result as anyone else in that position.
        """
        with patch(
            "openedx_authz.rest_api.utils.get_scopes_for_user_and_permission", return_value=[]
        ):
            self.assertFalse(has_visible_scope(self.USERNAME, self.ACTION, None))
