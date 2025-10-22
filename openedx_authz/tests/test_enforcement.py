"""
Comprehensive test suite for Open edX authorization enforcement using Casbin.

This module validates the authorization system implemented with Casbin, testing
various aspects of the permission model.
"""

import os
from typing import TypedDict
from unittest import TestCase

import casbin
from ddt import data, ddt, unpack

from openedx_authz import ROOT_DIRECTORY
from openedx_authz.tests.test_utils import (
    make_action_key,
    make_library_key,
    make_role_key,
    make_scope_key,
    make_user_key,
)


class AuthRequest(TypedDict):
    """
    Represents an authorization request with all necessary parameters.
    """

    subject: str
    action: str
    scope: str
    expected_result: bool


COMMON_ACTION_GROUPING = [
    # manage implies edit and delete
    ["g2", make_action_key("manage"), make_action_key("edit")],
    ["g2", make_action_key("manage"), make_action_key("delete")],
    # edit implies read and write
    ["g2", make_action_key("edit"), make_action_key("read")],
    ["g2", make_action_key("edit"), make_action_key("write")],
]


@ddt
class CasbinEnforcementTestCase(TestCase):
    """
    Test case for Casbin enforcement policies.

    This test class loads the model.conf and the provided policies and runs
    enforcement tests for different user roles and permissions.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Set up the Casbin enforcer."""
        super().setUpClass()

        engine_config_dir = os.path.join(ROOT_DIRECTORY, "engine", "config")
        model_file = os.path.join(engine_config_dir, "model.conf")

        if not os.path.isfile(model_file):
            raise FileNotFoundError(f"Model file not found: {model_file}")

        cls.enforcer = casbin.Enforcer(model_file)

    def _load_policy(self, policy: list[str]) -> None:
        """
        Load policy rules into the Casbin enforcer.

        This method clears any existing policies and loads the provided policy rules
        into the appropriate policy stores (p for policies, g for role assignments,
        g2 for action groupings).

        Args:
            policy (list[str]): List of policy rules where each rule is a
                list starting with the rule type ('p', 'g', or 'g2') followed by
                the rule parameters.

        Raises:
            ValueError: If a policy rule has an invalid type (not 'p', 'g', or 'g2').
        """
        self.enforcer.clear_policy()
        for rule in policy:
            if rule[0] == "p":
                self.enforcer.add_named_policy("p", rule[1:])
            elif rule[0] == "g":
                self.enforcer.add_named_grouping_policy("g", rule[1:])
            elif rule[0] == "g2":
                self.enforcer.add_named_grouping_policy("g2", rule[1:])
            else:
                raise ValueError(f"Invalid policy rule: {rule}")

    def _test_enforcement(self, policy: list[str], request: AuthRequest) -> None:
        """
        Helper method to test enforcement and provide detailed feedback.

        Args:
            policy (list[str]): A list of policy rules to load into the enforcer
            request (AuthRequest): An authorization request containing all necessary parameters
        """
        self._load_policy(policy)
        subject, action, scope = request["subject"], request["action"], request["scope"]
        result = self.enforcer.enforce(subject, action, scope)
        error_msg = f"Request: {subject} {action} {scope}"
        self.assertEqual(result, request["expected_result"], error_msg)


@ddt
class SystemWideRoleTests(CasbinEnforcementTestCase):
    """
    Tests for system-wide roles with global access permissions.

    This test class verifies that users assigned to system-wide roles (with global scope "*")
    can access resources across all scopes and namespaces. Platform administrators should
    have unrestricted access to manage any resource in the system, regardless of the
    specific scope (organization, course, library, etc.).
    """

    POLICY = [
        ["p", make_role_key("platform_admin"), make_action_key("manage"), "*", "allow"],
        ["g", make_user_key("user-1"), make_role_key("platform_admin"), "*"],
    ] + COMMON_ACTION_GROUPING

    GENERAL_CASES = [
        {
            "subject": make_user_key("user-1"),
            "action": make_action_key("manage"),
            "scope": "*",
            "expected_result": True,
        },
        {
            "subject": make_user_key("user-1"),
            "action": make_action_key("manage"),
            "scope": make_scope_key("org", "any-org"),
            "expected_result": True,
        },
        {
            "subject": make_user_key("user-1"),
            "action": make_action_key("manage"),
            "scope": make_scope_key("course", "course-v1:any-org+any-course+any-course-run"),
            "expected_result": True,
        },
        {
            "subject": make_user_key("user-1"),
            "action": make_action_key("manage"),
            "scope": make_library_key("lib:DemoX:CSPROB"),
            "expected_result": True,
        },
    ]

    @data(*GENERAL_CASES)
    def test_platform_admin_general_access(self, request: AuthRequest):
        """Test that platform administrators have full access to all resources."""
        self._test_enforcement(self.POLICY, request)


@ddt
class ActionGroupingTests(CasbinEnforcementTestCase):
    """
    Tests for action grouping and permission inheritance.

    This test class verifies that action grouping works correctly, where high-level
    actions (like 'manage') automatically grant access to lower-level actions
    (like 'edit', 'read', 'write', 'delete') through the g2 grouping mechanism.
    """

    POLICY = [
        [
            "p",
            make_role_key("role-1"),
            make_action_key("manage"),
            make_scope_key("org", "*"),
            "allow",
        ],
        [
            "g",
            make_user_key("user-1"),
            make_role_key("role-1"),
            make_scope_key("org", "any-org"),
        ],
    ] + COMMON_ACTION_GROUPING

    CASES = [
        {
            "subject": make_user_key("user-1"),
            "action": make_action_key("edit"),
            "scope": make_scope_key("org", "any-org"),
            "expected_result": True,
        },
        {
            "subject": make_user_key("user-1"),
            "action": make_action_key("read"),
            "scope": make_scope_key("org", "any-org"),
            "expected_result": True,
        },
        {
            "subject": make_user_key("user-1"),
            "action": make_action_key("write"),
            "scope": make_scope_key("org", "any-org"),
            "expected_result": True,
        },
        {
            "subject": make_user_key("user-1"),
            "action": make_action_key("delete"),
            "scope": make_scope_key("org", "any-org"),
            "expected_result": True,
        },
    ]

    @data(*CASES)
    def test_action_grouping_access(self, request: AuthRequest):
        """Test that users have access through action grouping."""
        self._test_enforcement(self.POLICY, request)


@ddt
class RoleAssignmentTests(CasbinEnforcementTestCase):
    """
    Tests for role assignment and scoped authorization.

    This test class verifies that users with different roles can access resources
    within their assigned scopes.
    """

    POLICY = [
        # Policies
        ["p", make_role_key("platform_admin"), make_action_key("manage"), "*", "allow"],
        [
            "p",
            make_role_key("org_admin"),
            make_action_key("manage"),
            make_scope_key("org", "*"),
            "allow",
        ],
        [
            "p",
            make_role_key("org_editor"),
            make_action_key("edit"),
            make_scope_key("org", "*"),
            "allow",
        ],
        [
            "p",
            make_role_key("org_author"),
            make_action_key("write"),
            make_scope_key("org", "*"),
            "allow",
        ],
        [
            "p",
            make_role_key("course_admin"),
            make_action_key("manage"),
            make_scope_key("course", "*"),
            "allow",
        ],
        [
            "p",
            make_role_key("library_admin"),
            make_action_key("manage"),
            make_scope_key("lib", "*"),
            "allow",
        ],
        [
            "p",
            make_role_key("library_editor"),
            make_action_key("edit"),
            make_scope_key("lib", "*"),
            "allow",
        ],
        [
            "p",
            make_role_key("library_reviewer"),
            make_action_key("read"),
            make_scope_key("lib", "*"),
            "allow",
        ],
        [
            "p",
            make_role_key("library_author"),
            make_action_key("write"),
            make_scope_key("lib", "*"),
            "allow",
        ],
        # Role assignments
        ["g", make_user_key("user-1"), make_role_key("platform_admin"), "*"],
        [
            "g",
            make_user_key("user-2"),
            make_role_key("org_admin"),
            make_scope_key("org", "any-org"),
        ],
        [
            "g",
            make_user_key("user-3"),
            make_role_key("org_editor"),
            make_scope_key("org", "any-org"),
        ],
        [
            "g",
            make_user_key("user-4"),
            make_role_key("org_author"),
            make_scope_key("org", "any-org"),
        ],
        [
            "g",
            make_user_key("user-5"),
            make_role_key("course_admin"),
            make_scope_key("course", "course-v1:any-org+any-course+any-course-run"),
        ],
        [
            "g",
            make_user_key("user-6"),
            make_role_key("library_admin"),
            make_library_key("lib:DemoX:CSPROB"),
        ],
        [
            "g",
            make_user_key("user-7"),
            make_role_key("library_editor"),
            make_library_key("lib:DemoX:CSPROB"),
        ],
        [
            "g",
            make_user_key("user-8"),
            make_role_key("library_reviewer"),
            make_library_key("lib:DemoX:CSPROB"),
        ],
        [
            "g",
            make_user_key("user-9"),
            make_role_key("library_author"),
            make_library_key("lib:DemoX:CSPROB"),
        ],
    ] + COMMON_ACTION_GROUPING

    CASES = [
        {
            "subject": make_user_key("user-1"),
            "action": make_action_key("manage"),
            "scope": make_scope_key("org", "any-org"),
            "expected_result": True,
        },
        {
            "subject": make_user_key("user-2"),
            "action": make_action_key("manage"),
            "scope": make_scope_key("org", "any-org"),
            "expected_result": True,
        },
        {
            "subject": make_user_key("user-3"),
            "action": make_action_key("edit"),
            "scope": make_scope_key("org", "any-org"),
            "expected_result": True,
        },
        {
            "subject": make_user_key("user-4"),
            "action": make_action_key("write"),
            "scope": make_scope_key("org", "any-org"),
            "expected_result": True,
        },
        {
            "subject": make_user_key("user-5"),
            "action": make_action_key("manage"),
            "scope": make_scope_key("course", "course-v1:any-org+any-course+any-course-run"),
            "expected_result": True,
        },
        {
            "subject": make_user_key("user-6"),
            "action": make_action_key("manage"),
            "scope": make_library_key("lib:DemoX:CSPROB"),
            "expected_result": True,
        },
        {
            "subject": make_user_key("user-7"),
            "action": make_action_key("edit"),
            "scope": make_library_key("lib:DemoX:CSPROB"),
            "expected_result": True,
        },
        {
            "subject": make_user_key("user-8"),
            "action": make_action_key("read"),
            "scope": make_library_key("lib:DemoX:CSPROB"),
            "expected_result": True,
        },
        {
            "subject": make_user_key("user-9"),
            "action": make_action_key("write"),
            "scope": make_library_key("lib:DemoX:CSPROB"),
            "expected_result": True,
        },
    ]

    @data(*CASES)
    def test_role_assignment_access(self, request: AuthRequest):
        """Test that users have access through role assignment."""
        self._test_enforcement(self.POLICY, request)


@ddt
class DeniedAccessTests(CasbinEnforcementTestCase):
    """Tests for denied access scenarios.

    This test class verifies that the authorization system correctly denies access
    when explicit deny rules override allow rules.
    """

    POLICY = [
        ["p", make_role_key("platform_admin"), make_action_key("manage"), "*", "allow"],
        [
            "p",
            make_role_key("platform_admin"),
            make_action_key("manage"),
            make_scope_key("org", "restricted-org"),
            "deny",
        ],
        ["g", make_user_key("user-1"), make_role_key("platform_admin"), "*"],
    ] + COMMON_ACTION_GROUPING

    CASES = [
        {
            "subject": make_user_key("user-1"),
            "action": make_action_key("manage"),
            "scope": make_scope_key("org", "allowed-org"),
            "expected_result": True,
        },
        {
            "subject": make_user_key("user-1"),
            "action": make_action_key("manage"),
            "scope": make_scope_key("org", "restricted-org"),
            "expected_result": False,
        },
        {
            "subject": make_user_key("user-1"),
            "action": make_action_key("edit"),
            "scope": make_scope_key("org", "restricted-org"),
            "expected_result": False,
        },
        {
            "subject": make_user_key("user-1"),
            "action": make_action_key("read"),
            "scope": make_scope_key("org", "restricted-org"),
            "expected_result": False,
        },
        {
            "subject": make_user_key("user-1"),
            "action": make_action_key("write"),
            "scope": make_scope_key("org", "restricted-org"),
            "expected_result": False,
        },
        {
            "subject": make_user_key("user-1"),
            "action": make_action_key("delete"),
            "scope": make_scope_key("org", "restricted-org"),
            "expected_result": False,
        },
    ]

    @data(*CASES)
    def test_denied_access(self, request: AuthRequest):
        """Test that users have denied access."""
        self._test_enforcement(self.POLICY, request)


@ddt
class WildcardScopeTests(CasbinEnforcementTestCase):
    """Tests for wildcard scope authorization patterns.

    Verifies that users with roles assigned to wildcard scopes (like "*" for global access
    or "org^*" for organization-wide access) can properly access resources within their
    authorized scope boundaries.

    TODO: this needs to be updated with the latest changes in the model.
    """

    POLICY = [
        # Policies
        ["p", make_role_key("platform_admin"), make_action_key("manage"), "*", "allow"],
        [
            "p",
            make_role_key("org_admin"),
            make_action_key("manage"),
            make_scope_key("org", "*"),
            "allow",
        ],
        [
            "p",
            make_role_key("course_admin"),
            make_action_key("manage"),
            make_scope_key("course", "*"),
            "allow",
        ],
        [
            "p",
            make_role_key("library_admin"),
            make_action_key("manage"),
            make_scope_key("lib", "*"),
            "allow",
        ],
        # Role assignments
        ["g", make_user_key("user-1"), make_role_key("platform_admin"), "*"],
        ["g", make_user_key("user-2"), make_role_key("org_admin"), "*"],
        ["g", make_user_key("user-3"), make_role_key("course_admin"), "*"],
        ["g", make_user_key("user-4"), make_role_key("library_admin"), "*"],
    ] + COMMON_ACTION_GROUPING

    @data(
        ("*", True),
        (make_scope_key("org", "MIT"), True),
        (make_scope_key("course", "course-v1:OpenedX+DemoX+CS101"), True),
        (make_library_key("lib:OpenedX:math-basics"), True),
    )
    @unpack
    def test_wildcard_global_access(self, scope: str, expected_result: bool):
        """Test that users have access through wildcard global scope."""
        request = {
            "subject": make_user_key("user-1"),
            "action": make_action_key("manage"),
            "scope": scope,
            "expected_result": expected_result,
        }
        self._test_enforcement(self.POLICY, request)

    @data(
        ("*", False),
        (make_scope_key("org", "MIT"), True),
        (make_scope_key("course", "course-v1:OpenedX+DemoX+CS101"), False),
        (make_library_key("lib:OpenedX:math-basics"), False),
    )
    @unpack
    def test_wildcard_org_access(self, scope: str, expected_result: bool):
        """Test that users have access through wildcard org scope."""
        request = {
            "subject": make_user_key("user-2"),
            "action": make_action_key("manage"),
            "scope": scope,
            "expected_result": expected_result,
        }
        self._test_enforcement(self.POLICY, request)

    @data(
        ("*", False),
        (make_scope_key("org", "MIT"), False),
        (make_scope_key("course", "course-v1:OpenedX+DemoX+CS101"), True),
        (make_library_key("lib:OpenedX:math-basics"), False),
    )
    @unpack
    def test_wildcard_course_access(self, scope: str, expected_result: bool):
        """Test that users have access through wildcard course scope."""
        request = {
            "subject": make_user_key("user-3"),
            "action": make_action_key("manage"),
            "scope": scope,
            "expected_result": expected_result,
        }
        self._test_enforcement(self.POLICY, request)

    @data(
        ("*", False),
        (make_scope_key("org", "MIT"), False),
        (make_scope_key("course", "course-v1:OpenedX+DemoX+CS101"), False),
        (make_library_key("lib:OpenedX:math-basics"), True),
    )
    @unpack
    def test_wildcard_library_access(self, scope: str, expected_result: bool):
        """Test that users have access through wildcard library scope."""
        request = {
            "subject": make_user_key("user-4"),
            "action": make_action_key("manage"),
            "scope": scope,
            "expected_result": expected_result,
        }
        self._test_enforcement(self.POLICY, request)
