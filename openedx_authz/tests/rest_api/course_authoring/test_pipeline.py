"""Unit tests for the course-authoring visibility pipeline step.

The three-tier cascade (course override, else org override, else platform
default) is edx-platform's ``CourseWaffleFlag.is_enabled()``, not importable
in this repo's standalone test suite. ``CourseWaffleFlagMock`` stands in for
it, so the truth table can still be exercised end to end.
"""

from unittest.mock import MagicMock, patch

from ddt import data, ddt, unpack
from django.test import TestCase, override_settings

from openedx_authz.api.data import ContentLibraryData, CourseOverviewData, OrgCourseOverviewGlobData
from openedx_authz.filters import PermissionValidationRequested, RoleAssignmentRequested, RoleRemovalRequested
from openedx_authz.rest_api.v1.course_authoring.pipeline import (
    CourseAuthoringPermissionValidationFilter,
    CourseAuthoringRoleAssignmentFilter,
    CourseAuthoringRoleRemovalFilter,
    is_scope_visible,
)

COURSE_SCOPE = "course-v1:Org1+COURSE1+2024"
OTHER_COURSE_SCOPE = "course-v1:Org1+COURSE2+2024"
LIB_SCOPE = "lib:Org1:LIB1"
ORG_GLOB_COURSE_SCOPE = OrgCourseOverviewGlobData.build_external_key("Org1")


class CourseWaffleFlagMock:
    """Stand-in for edx-platform's ``CourseWaffleFlag``, not importable in this repo's standalone suite."""

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


@ddt
class TestIsScopeVisible(TestCase):
    """Test is_scope_visible, dispatching to the right override tier depending on the scope's type."""

    @data(
        (False, None, None, False),
        (True, None, None, True),
        (False, True, None, True),
        (True, False, None, False),
        (False, None, True, True),
        (True, None, False, False),
    )
    @unpack
    def test_course_scope_follows_the_truth_table(
        self, platform: bool, org_override: bool | None, course_override: bool | None, expected: bool
    ):
        """Test is_scope_visible for a concrete course scope against override combinations.

        Expected result:
            - The scope is visible exactly when course override wins, else org
              override, else platform default.
        """
        with patch(
            "openedx_authz.rest_api.v1.course_authoring.pipeline.enable_authz_course_authoring",
            CourseWaffleFlagMock(platform, org_override, course_override),
        ):
            self.assertEqual(is_scope_visible(CourseOverviewData(external_key=COURSE_SCOPE)), expected)

    def test_library_scope_is_always_visible_regardless_of_the_flag(self):
        """Test is_scope_visible for a library scope.

        Expected result:
            - The scope is always visible, since it isn't course-authoring-gated.
        """
        with patch(
            "openedx_authz.rest_api.v1.course_authoring.pipeline.enable_authz_course_authoring", return_value=False
        ):
            self.assertTrue(is_scope_visible(ContentLibraryData(external_key=LIB_SCOPE)))

    @data(
        ("on", False, True),
        ("off", True, False),
        ("unset", True, True),
    )
    @unpack
    def test_org_glob_scope_org_override_takes_precedence(
        self, override_choice: str, platform_default: bool, expected: bool
    ):
        """Test is_scope_visible for an org-glob scope against org/platform combinations.

        Expected result:
            - The scope follows the org override when set, else the platform default.
        """
        mock_org_model = MagicMock()
        mock_org_model.ALL_CHOICES.on = "on"
        mock_org_model.ALL_CHOICES.off = "off"
        mock_org_model.override_value.return_value = override_choice
        scope = OrgCourseOverviewGlobData(external_key=ORG_GLOB_COURSE_SCOPE)

        with patch(
            "openedx_authz.rest_api.v1.course_authoring.pipeline.WaffleFlagOrgOverrideModel", mock_org_model
        ), patch(
            "openedx_authz.rest_api.v1.course_authoring.pipeline.AUTHZ_COURSE_AUTHORING_FLAG",
            MagicMock(name="authz.enable_course_authoring"),
        ), patch(
            "openedx_authz.rest_api.v1.course_authoring.pipeline.enable_authz_course_authoring",
            return_value=platform_default,
        ):
            self.assertEqual(is_scope_visible(scope), expected)


@ddt
class TestCourseAuthoringPermissionValidationFilter(TestCase):
    """Test operation-specific course-authoring visibility steps."""

    def test_marks_allowed_false_instead_of_dropping_when_the_item_has_an_allowed_key(self):
        """Test run_filter with an item that carries an ``allowed`` key, mirroring PermissionValidationMeView.

        Expected result:
            - The item survives, but with ``allowed`` flipped to ``False``.
        """
        items = [{"scope": COURSE_SCOPE, "action": "view", "allowed": True}]
        with patch(
            "openedx_authz.rest_api.v1.course_authoring.pipeline.enable_authz_course_authoring", return_value=False
        ):
            result = CourseAuthoringPermissionValidationFilter(
                filter_type="test", running_pipeline=[]
            ).run_filter(
                items=items, errors=[]
            )

        self.assertEqual(
            result,
            {"items": [{"scope": COURSE_SCOPE, "action": "view", "allowed": False}], "errors": []},
        )

    def test_leaves_any_scope_items_untouched(self):
        """Test run_filter with an item whose scope is None (an any-scope check).

        Expected result:
            - The item survives unchanged; there's no single scope to check visibility against.
        """
        items = [
            {"scope": None, "action": "view", "allowed": True},
            {"action": "view", "allowed": True},
            {"scope": "", "action": "view", "allowed": True},
        ]
        with patch(
            "openedx_authz.rest_api.v1.course_authoring.pipeline.enable_authz_course_authoring", return_value=False
        ):
            result = CourseAuthoringPermissionValidationFilter(
                filter_type="test", running_pipeline=[]
            ).run_filter(
                items=items, errors=[]
            )

        self.assertEqual(result, {"items": items, "errors": []})

    def test_assignment_keeps_visible_scopes_and_preserves_previous_errors(self):
        """Partial rejection keeps available writes and earlier pipeline errors."""
        items = {"role": "course_staff", "users": ["alice", "bob"], "scopes": [COURSE_SCOPE, LIB_SCOPE]}
        previous_errors = [{"error": "previous_step"}]
        with patch(
            "openedx_authz.rest_api.v1.course_authoring.pipeline.enable_authz_course_authoring", return_value=False
        ):
            result = CourseAuthoringRoleAssignmentFilter(filter_type="test", running_pipeline=[]).run_filter(
                items=items, errors=previous_errors
            )

        self.assertEqual(result["items"], {**items, "scopes": [LIB_SCOPE]})
        self.assertEqual(result["errors"], [
            {"error": "previous_step"},
            {"user_identifier": "alice", "scope": COURSE_SCOPE, "error": "scope_not_available"},
            {"user_identifier": "bob", "scope": COURSE_SCOPE, "error": "scope_not_available"},
        ])
        self.assertEqual(previous_errors, [{"error": "previous_step"}])
        self.assertEqual(items["scopes"], [COURSE_SCOPE, LIB_SCOPE])

    def test_removal_preserves_extra_fields(self):
        """Additional metadata must not turn a removal into an assignment."""
        items = {"role": "course_staff", "users": ["alice"], "scope": COURSE_SCOPE, "scopes": [LIB_SCOPE]}
        with patch(
            "openedx_authz.rest_api.v1.course_authoring.pipeline.enable_authz_course_authoring", return_value=False
        ):
            result = CourseAuthoringRoleRemovalFilter(filter_type="test", running_pipeline=[]).run_filter(
                items=items, errors=[]
            )

        self.assertEqual(result["items"], {**items, "users": []})
        self.assertEqual(result["errors"], [
            {"user_identifier": "alice", "scope": COURSE_SCOPE, "error": "scope_not_available"},
        ])

    @data(
        (PermissionValidationRequested, [{"action": "view", "allowed": True}]),
        (RoleAssignmentRequested, {"role": "course_staff", "users": ["alice"], "scopes": [COURSE_SCOPE]}),
        (RoleRemovalRequested, {"role": "course_staff", "users": ["alice"], "scope": COURSE_SCOPE}),
    )
    @unpack
    @override_settings(OPEN_EDX_FILTERS_CONFIG={})
    def test_unconfigured_hook_returns_original_data(self, filter_class, items):
        """Each public hook passes through its payload when no pipeline is configured."""
        filtered, errors = filter_class.run_filter(items=items)
        self.assertEqual(filtered, items)
        self.assertEqual(errors, [])
