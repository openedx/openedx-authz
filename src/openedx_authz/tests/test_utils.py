"""Test utilities for creating namespaced keys using class constants."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from ddt import data, ddt, unpack
from django.test import TestCase

from openedx_authz.api.data import (
    GLOBAL_SCOPE_WILDCARD,
    ActionData,
    ContentLibraryData,
    CourseOverviewData,
    RoleData,
    ScopeData,
    UserData,
)
from openedx_authz.utils import get_waffle_flag_states

FLAG_NAME = "authz.enable_course_authoring"


def make_policy(role_key: str, action_key: str, scope_key: str, effect: str = "allow") -> list[str]:
    """Create a policy.

    Args:
        role_key (str): The role key of the policy.
        action_key (str): The action key of the policy.
        scope_key (str): The scope key of the policy.
        effect (str): The effect of the policy.

    Returns:
        list[str]: The policy.
    """
    return [
        "p",
        make_role_key(role_key),
        make_action_key(action_key),
        make_wildcard_key(scope_key),
        effect,
    ]


def make_library_assignment(user_key: str, role_key: str, scope_key: str) -> list[str]:
    """Create a library assignment.

    Args:
        user_key (str): The user key of the assignment.
        role_key (str): The role key of the assignment.
        scope_key (str): The scope key of the assignment.
    """
    return [
        "g",
        make_user_key(user_key),
        make_role_key(role_key),
        make_library_key(scope_key),
    ]


def make_course_assignment(user_key: str, role_key: str, scope_key: str) -> list[str]:
    """Create a course assignment.

    Args:
        user_key (str): The user key of the assignment.
        role_key (str): The role key of the assignment.
        scope_key (str): The scope key of the assignment.

    Returns:
        list[str]: The course assignment.
    """
    return [
        "g",
        make_user_key(user_key),
        make_role_key(role_key),
        make_course_key(scope_key),
    ]


def make_course_case(username: str, permission: str, scope: str, expected_result: bool) -> dict:
    """Create a course case test data.

    Args:
        username (str): The username of the user.
        permission (str): The permission to test.
        scope (str): The scope to test.
        expected_result (bool): The expected result.

    Returns:
        dict: The course case.
    """
    return {
        "subject": make_user_key(username),
        "action": make_action_key(permission),
        "scope": make_course_key(scope),
        "expected_result": expected_result,
    }


def make_library_case(username: str, permission: str, scope: str, expected_result: bool) -> dict:
    """Create a library case test data.

    Args:
        username (str): The username of the user.
        permission (str): The permission to test.
        scope (str): The scope to test.
        expected_result (bool): The expected result.
    """
    return {
        "subject": make_user_key(username),
        "action": make_action_key(permission),
        "scope": make_library_key(scope),
        "expected_result": expected_result,
    }


def make_user_key(key: str) -> str:
    """Create a namespaced user key.

    Args:
        key: The user identifier (e.g., 'user-1', 'alice')

    Returns:
        str: Namespaced user key (e.g., 'user^user-1')
    """
    return f"{UserData.NAMESPACE}{UserData.SEPARATOR}{key}"


def make_role_key(key: str) -> str:
    """Create a namespaced role key.

    Args:
        key: The role identifier (e.g., 'platform_admin', 'library_editor')

    Returns:
        str: Namespaced role key (e.g., 'role^platform_admin')
    """
    return f"{RoleData.NAMESPACE}{RoleData.SEPARATOR}{key}"


def make_action_key(key: str) -> str:
    """Create a namespaced action key.

    Args:
        key: The action identifier (e.g., 'manage', 'edit', 'read')

    Returns:
        str: Namespaced action key (e.g., 'act^manage')
    """
    return f"{ActionData.NAMESPACE}{ActionData.SEPARATOR}{key}"


def make_library_key(key: str) -> str:
    """Create a namespaced library key.

    Args:
        key: The library identifier (e.g., 'lib:DemoX:CSPROB')

    Returns:
        str: Namespaced library key (e.g., 'lib^lib:DemoX:CSPROB')
    """
    return f"{ContentLibraryData.NAMESPACE}{ContentLibraryData.SEPARATOR}{key}"


def make_course_key(key: str) -> str:
    """Create a namespaced course key.

    Args:
        key: The course identifier (e.g., 'course-v1:DemoX+DemoCourse+2026_T1')

    Returns:
        str: Namespaced course key (e.g., 'course-v1^course-v1:DemoX+DemoCourse+2026_T1')
    """
    return f"{CourseOverviewData.NAMESPACE}{CourseOverviewData.SEPARATOR}{key}"


def make_scope_key(namespace: str, key: str) -> str:
    """Create a namespaced scope key with custom namespace.

    Args:
        namespace: The scope namespace (e.g., 'org', 'course')
        key: The scope identifier (e.g., 'any-org', 'course-v1:...')

    Returns:
        str: Namespaced scope key (e.g., 'org^any-org')
    """
    return f"{namespace}{ScopeData.SEPARATOR}{key}"


def make_wildcard_key(namespace: str) -> str:
    """Create a wildcard pattern for a given namespace.

    Args:
        namespace (str): The namespace to create a wildcard for (e.g., 'lib', 'org', 'course')

    Returns:
        str: Wildcard pattern (e.g., 'lib^*', 'org^*', 'course^*')
    """
    return f"{namespace}{ScopeData.SEPARATOR}{GLOBAL_SCOPE_WILDCARD}"


@ddt
class TestGetWaffleFlagStates(TestCase):
    """Test get_waffle_flag_states, which reports the course-authoring flag's state at each tier."""

    def _mock_override_model(self, override_rows: list):
        """Build a mock override model. override_rows is a list of (key, override_choice) tuples."""
        mock_model = MagicMock()
        mock_model.objects.current_set.return_value.filter.return_value.values_list.return_value = override_rows
        return mock_model

    @data(True, False)
    def test_global_tier_follows_the_platform_flag(self, platform_enabled: bool):
        """Test get_waffle_flag_states' global key.

        Expected result:
            - Matches global waffle flag result.
        """
        with patch(
            "openedx_authz.utils.Flag",
            MagicMock(objects=MagicMock(
                filter=MagicMock(return_value=MagicMock(first=MagicMock(
                    return_value=SimpleNamespace(everyone=platform_enabled)
                )))
            )),
        ), patch(
            "openedx_authz.utils.AUTHZ_COURSE_AUTHORING_FLAG", SimpleNamespace(name=FLAG_NAME)
        ), patch(
            "openedx_authz.utils.WaffleFlagOrgOverrideModel", self._mock_override_model([])
        ), patch(
            "openedx_authz.utils.WaffleFlagCourseOverrideModel", self._mock_override_model([])
        ):
            self.assertEqual(get_waffle_flag_states()["global"], platform_enabled)

    @data(
        ([("Org1", "on")], {"on": ["Org1"], "off": []}),
        ([("Org1", "off")], {"on": [], "off": ["Org1"]}),
        ([("Org1", "on"), ("Org2", "off")], {"on": ["Org1"], "off": ["Org2"]}),
        ([], {"on": [], "off": []}),
    )
    @unpack
    def test_org_tier_splits_active_overrides_by_choice(self, override_rows: list, expected: dict):
        """Test get_waffle_flag_states' org key.

        Expected result:
            - Orgs with an enabled override are split into 'on' and 'off' lists,
              by the override's choice.
        """
        with patch(
            "openedx_authz.utils.Flag",
            MagicMock(objects=MagicMock(
                filter=MagicMock(return_value=MagicMock(first=MagicMock(
                    return_value=SimpleNamespace(everyone=False)
                )))
            )),
        ), patch(
            "openedx_authz.utils.AUTHZ_COURSE_AUTHORING_FLAG", SimpleNamespace(name=FLAG_NAME)
        ), patch(
            "openedx_authz.utils.WaffleFlagOrgOverrideModel", self._mock_override_model(override_rows)
        ), patch(
            "openedx_authz.utils.WaffleFlagCourseOverrideModel", self._mock_override_model([])
        ):
            self.assertEqual(get_waffle_flag_states()["org_overrides"], expected)

    @data(
        ([("course-v1:Org1+COURSE1+2024", "on")], {"on": ["course-v1:Org1+COURSE1+2024"], "off": []}),
        ([("course-v1:Org1+COURSE1+2024", "off")], {"on": [], "off": ["course-v1:Org1+COURSE1+2024"]}),
        (
            [("course-v1:Org1+COURSE1+2024", "on"), ("course-v1:Org1+COURSE2+2024", "off")],
            {"on": ["course-v1:Org1+COURSE1+2024"], "off": ["course-v1:Org1+COURSE2+2024"]},
        ),
        ([], {"on": [], "off": []}),
    )
    @unpack
    def test_course_tier_splits_active_overrides_by_choice(self, override_rows: list, expected: dict):
        """Test get_waffle_flag_states' course key.

        Expected result:
            - Courses with an enabled override are split into 'on' and 'off' lists,
              by the override's choice. Course keys are stringified.
        """
        with patch(
            "openedx_authz.utils.Flag",
            MagicMock(objects=MagicMock(
                filter=MagicMock(return_value=MagicMock(first=MagicMock(
                    return_value=SimpleNamespace(everyone=False)
                )))
            )),
        ), patch(
            "openedx_authz.utils.AUTHZ_COURSE_AUTHORING_FLAG", SimpleNamespace(name=FLAG_NAME)
        ), patch(
            "openedx_authz.utils.WaffleFlagOrgOverrideModel", self._mock_override_model([])
        ), patch(
            "openedx_authz.utils.WaffleFlagCourseOverrideModel", self._mock_override_model(override_rows)
        ):
            self.assertEqual(get_waffle_flag_states()["course_overrides"], expected)

    def test_all_three_tiers_are_independent(self):
        """Test get_waffle_flag_states with each tier in a different state.

        Expected result:
            - Each key reflects only its own tier, not a blend of the others.
        """
        with patch(
            "openedx_authz.utils.Flag",
            MagicMock(objects=MagicMock(
                filter=MagicMock(return_value=MagicMock(first=MagicMock(
                    return_value=SimpleNamespace(everyone=False)
                )))
            )),
        ), patch(
            "openedx_authz.utils.AUTHZ_COURSE_AUTHORING_FLAG", SimpleNamespace(name=FLAG_NAME)
        ), patch(
            "openedx_authz.utils.WaffleFlagOrgOverrideModel", self._mock_override_model([("Org1", "on")])
        ), patch(
            "openedx_authz.utils.WaffleFlagCourseOverrideModel", self._mock_override_model([])
        ):
            self.assertEqual(
                get_waffle_flag_states(),
                {
                    "global": False,
                    "org_overrides": {"on": ["Org1"], "off": []},
                    "course_overrides": {"on": [], "off": []},
                },
            )
