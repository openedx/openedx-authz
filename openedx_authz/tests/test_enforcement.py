"""
Tests for Casbin enforcement using model.conf and authz.policy files.

This module contains comprehensive tests for the authorization enforcement
using Casbin with the configured model and policy files.
"""

import os
from typing import TypedDict
from unittest import TestCase

import casbin
from ddt import data, ddt


class AuthRequest(TypedDict):
    """
    Represents an authorization request with all necessary parameters.
    """

    subject: str
    action: str
    object: str
    scope: str
    expected_result: bool


@ddt
class CasbinEnforcementTestCase(TestCase):
    """
    Test case for Casbin enforcement policies.

    This test class loads the model.conf and authz.policy files and runs
    enforcement tests for different user roles and permissions.
    """

    @classmethod
    def setUpClass(cls):
        """Set up the Casbin enforcer with model and policy files."""
        super().setUpClass()

        engine_config_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "engine", "config")
        test_config_dir = os.path.join(os.path.dirname(__file__), "config")

        model_file = os.path.join(engine_config_dir, "model.conf")
        policy_file = os.path.join(test_config_dir, "authz.policy")

        if not os.path.isfile(model_file):
            raise FileNotFoundError(f"Model file not found: {model_file}")
        if not os.path.isfile(policy_file):
            raise FileNotFoundError(f"Policy file not found: {policy_file}")

        cls.enforcer = casbin.Enforcer(model_file, policy_file)

    def _test_enforcement(self, request: AuthRequest):
        """
        Helper method to test enforcement and provide detailed feedback.

        Args:
            request (AuthRequest): An authorization request containing all necessary parameters
        """
        subject, action, obj, scope = request["subject"], request["action"], request["object"], request["scope"]
        result = self.enforcer.enforce(subject, action, obj, scope)
        error_msg = f"Request: {subject} {action} {obj} {scope}"
        self.assertEqual(result, request["expected_result"], error_msg)


@ddt
class PlatformAdministratorTests(CasbinEnforcementTestCase):
    """Tests for platform administrator access."""

    platform_admin_cases = [
        {
            "subject": "user:admin",
            "action": "act:manage",
            "object": "lib:math-basics",
            "scope": "*",
            "expected_result": True,
        },
        {
            "subject": "user:admin",
            "action": "act:delete",
            "object": "lib:science-101",
            "scope": "*",
            "expected_result": True,
        },
        {
            "subject": "user:admin",
            "action": "act:read",
            "object": "lib:any-library",
            "scope": "*",
            "expected_result": True,
        },
        {
            "subject": "user:admin",
            "action": "act:write",
            "object": "lib:any-library",
            "scope": "*",
            "expected_result": True,
        },
        {
            "subject": "user:admin",
            "action": "act:delete",
            "object": "lib:any-library",
            "scope": "*",
            "expected_result": True,
        },
    ]

    @data(*platform_admin_cases)
    def test_platform_admin_access(self, request: AuthRequest):
        """Test that platform administrators have full access to all resources."""
        self._test_enforcement(request)


@ddt
class OrganizationAdministratorTests(CasbinEnforcementTestCase):
    """Tests for organization administrator access."""

    alice_allowed_cases = [
        {
            "subject": "user:alice",
            "action": "act:manage",
            "object": "lib:openedx-library",
            "scope": "org:OpenedX",
            "expected_result": True,
        },
        {
            "subject": "user:alice",
            "action": "act:delete",
            "object": "lib:openedx-content",
            "scope": "org:OpenedX",
            "expected_result": True,
        },
        {
            "subject": "user:alice",
            "action": "act:write",
            "object": "lib:math-basics",
            "scope": "org:OpenedX",
            "expected_result": True,
        },
        {
            "subject": "user:alice",
            "action": "act:read",
            "object": "lib:openedx-test",
            "scope": "org:OpenedX",
            "expected_result": True,
        },
        {
            "subject": "user:alice",
            "action": "act:write",
            "object": "lib:openedx-test",
            "scope": "org:OpenedX",
            "expected_result": True,
        },
        {
            "subject": "user:alice",
            "action": "act:delete",
            "object": "lib:openedx-test",
            "scope": "org:OpenedX",
            "expected_result": True,
        },
        {
            "subject": "user:alice",
            "action": "act:manage",
            "object": "lib:math-basics",
            "scope": "org:OpenedX",
            "expected_result": True,
        },
        {
            "subject": "user:alice",
            "action": "act:manage",
            "object": "lib:science-101",
            "scope": "org:OpenedX",
            "expected_result": True,
        },
        {
            "subject": "user:alice",
            "action": "act:edit",
            "object": "lib:science-101",
            "scope": "org:OpenedX",
            "expected_result": True,
        },
    ]

    alice_denied_cases = [
        {
            "subject": "user:alice",
            "action": "act:manage",
            "object": "lib:mit-library",
            "scope": "org:MIT",
            "expected_result": False,
        },
        {
            "subject": "user:alice",
            "action": "act:read",
            "object": "lib:mit-content",
            "scope": "org:MIT",
            "expected_result": False,
        },
        {
            "subject": "user:alice",
            "action": "act:manage",
            "object": "lib:openedx-lib",
            "scope": "*",
            "expected_result": False,
        },
    ]

    alice_restricted_cases = [
        {
            "subject": "user:alice",
            "action": "act:manage",
            "object": "lib:another-restricted-content",
            "scope": "org:OpenedX",
            "expected_result": False,
        },
        {
            "subject": "user:alice",
            "action": "act:edit",
            "object": "lib:another-restricted-content",
            "scope": "org:OpenedX",
            "expected_result": False,
        },
        {
            "subject": "user:alice",
            "action": "act:read",
            "object": "lib:another-restricted-content",
            "scope": "org:OpenedX",
            "expected_result": False,
        },
        {
            "subject": "user:alice",
            "action": "act:write",
            "object": "lib:another-restricted-content",
            "scope": "org:OpenedX",
            "expected_result": False,
        },
        {
            "subject": "user:alice",
            "action": "act:delete",
            "object": "lib:another-restricted-content",
            "scope": "org:OpenedX",
            "expected_result": False,
        },
    ]

    @data(*alice_allowed_cases)
    def test_alice_org_admin_allowed_access(self, request: AuthRequest):
        """Test that Alice (OpenedX org admin) has proper access within her scope."""
        self._test_enforcement(request)

    @data(*alice_denied_cases)
    def test_alice_cross_org_denied_access(self, request: AuthRequest):
        """Test that Alice is denied access outside her organization scope."""
        self._test_enforcement(request)

    @data(*alice_restricted_cases)
    def test_alice_restricted_content_denied(self, request: AuthRequest):
        """Test that Alice is denied access to restricted content."""
        self._test_enforcement(request)


@ddt
class OrganizationEditorTests(CasbinEnforcementTestCase):
    """Tests for organization editor access."""

    bob_allowed_cases = [
        {
            "subject": "user:bob",
            "action": "act:edit",
            "object": "lib:mit-course",
            "scope": "org:MIT",
            "expected_result": True,
        },
        {
            "subject": "user:bob",
            "action": "act:read",
            "object": "lib:mit-content",
            "scope": "org:MIT",
            "expected_result": True,
        },
        {
            "subject": "user:bob",
            "action": "act:write",
            "object": "lib:mit-data",
            "scope": "org:MIT",
            "expected_result": True,
        },
        {
            "subject": "user:bob",
            "action": "act:read",
            "object": "lib:mit-test",
            "scope": "org:MIT",
            "expected_result": True,
        },
        {
            "subject": "user:bob",
            "action": "act:write",
            "object": "lib:mit-test",
            "scope": "org:MIT",
            "expected_result": True,
        },
    ]

    bob_denied_higher_privilege = [
        {
            "subject": "user:bob",
            "action": "act:delete",
            "object": "lib:mit-course",
            "scope": "org:MIT",
            "expected_result": False,
        },
        {
            "subject": "user:bob",
            "action": "act:manage",
            "object": "lib:mit-course",
            "scope": "org:MIT",
            "expected_result": False,
        },
        {
            "subject": "user:bob",
            "action": "act:delete",
            "object": "lib:mit-test",
            "scope": "org:MIT",
            "expected_result": False,
        },
    ]

    bob_denied_restricted = [
        {
            "subject": "user:bob",
            "action": "act:edit",
            "object": "lib:restricted-content",
            "scope": "org:MIT",
            "expected_result": False,
        },
        {
            "subject": "user:bob",
            "action": "act:read",
            "object": "lib:restricted-content",
            "scope": "org:MIT",
            "expected_result": False,
        },
        {
            "subject": "user:bob",
            "action": "act:write",
            "object": "lib:restricted-content",
            "scope": "org:MIT",
            "expected_result": False,
        },
    ]

    bob_denied_scope_isolation = [
        {
            "subject": "user:bob",
            "action": "act:edit",
            "object": "lib:mit-course",
            "scope": "lib:mit-course",
            "expected_result": False,
        },
    ]

    paul_cases = [
        {
            "subject": "user:paul",
            "action": "act:edit",
            "object": "lib:openedx-lib",
            "scope": "org:OpenedX",
            "expected_result": True,
        },
        {
            "subject": "user:paul",
            "action": "act:edit",
            "object": "lib:mit-lib",
            "scope": "org:MIT",
            "expected_result": False,
        },
    ]

    @data(*bob_allowed_cases)
    def test_bob_org_editor_allowed_access(self, request: AuthRequest):
        """Test that Bob (MIT org editor) has proper edit access within his scope."""
        self._test_enforcement(request)

    @data(*bob_denied_higher_privilege)
    def test_bob_denied_higher_privileges(self, request: AuthRequest):
        """Test that Bob is denied higher privilege actions like delete/manage."""
        self._test_enforcement(request)

    @data(*bob_denied_restricted)
    def test_bob_denied_restricted_content(self, request: AuthRequest):
        """Test that Bob is denied access to restricted content."""
        self._test_enforcement(request)

    @data(*bob_denied_scope_isolation)
    def test_bob_denied_scope_isolation(self, request: AuthRequest):
        """Test that Bob is denied access when scope doesn't match his role scope."""
        self._test_enforcement(request)

    @data(*paul_cases)
    def test_paul_editor_access(self, request: AuthRequest):
        """Test Paul's editor access across different organizations."""
        self._test_enforcement(request)


@ddt
class LibraryAuthorTests(CasbinEnforcementTestCase):
    """Tests for library author access."""

    mary_allowed_cases = [
        {
            "subject": "user:mary",
            "action": "act:edit",
            "object": "lib:math-basics",
            "scope": "lib:math-basics",
            "expected_result": True,
        },
        {
            "subject": "user:mary",
            "action": "act:read",
            "object": "lib:math-basics",
            "scope": "lib:math-basics",
            "expected_result": True,
        },
        {
            "subject": "user:mary",
            "action": "act:write",
            "object": "lib:math-basics",
            "scope": "lib:math-basics",
            "expected_result": True,
        },
    ]

    mary_denied_higher_privilege = [
        {
            "subject": "user:mary",
            "action": "act:delete",
            "object": "lib:math-basics",
            "scope": "lib:math-basics",
            "expected_result": False,
        },
        {
            "subject": "user:mary",
            "action": "act:manage",
            "object": "lib:math-basics",
            "scope": "lib:math-basics",
            "expected_result": False,
        },
    ]

    mary_denied_cross_library = [
        {
            "subject": "user:mary",
            "action": "act:edit",
            "object": "lib:science-101",
            "scope": "lib:science-101",
            "expected_result": False,
        },
        {
            "subject": "user:mary",
            "action": "act:read",
            "object": "lib:science-101",
            "scope": "lib:science-101",
            "expected_result": False,
        },
    ]

    mary_denied_scope_isolation = [
        {
            "subject": "user:mary",
            "action": "act:edit",
            "object": "lib:math-basics",
            "scope": "org:OpenedX",
            "expected_result": False,
        },
    ]

    john_allowed_cases = [
        {
            "subject": "user:john",
            "action": "act:edit",
            "object": "lib:science-101",
            "scope": "lib:science-101",
            "expected_result": True,
        },
        {
            "subject": "user:john",
            "action": "act:read",
            "object": "lib:science-101",
            "scope": "lib:science-101",
            "expected_result": True,
        },
    ]

    john_denied_cross_library = [
        {
            "subject": "user:john",
            "action": "act:edit",
            "object": "lib:math-basics",
            "scope": "lib:math-basics",
            "expected_result": False,
        },
    ]

    @data(*mary_allowed_cases)
    def test_mary_library_author_allowed_access(self, request: AuthRequest):
        """Test that Mary has proper access to her assigned library."""
        self._test_enforcement(request)

    @data(*mary_denied_higher_privilege)
    def test_mary_denied_higher_privileges(self, request: AuthRequest):
        """Test that Mary is denied higher privilege actions."""
        self._test_enforcement(request)

    @data(*mary_denied_cross_library)
    def test_mary_denied_cross_library_access(self, request: AuthRequest):
        """Test that Mary is denied access to other libraries."""
        self._test_enforcement(request)

    @data(*mary_denied_scope_isolation)
    def test_mary_denied_scope_isolation(self, request: AuthRequest):
        """Test that Mary is denied access when scope doesn't match her role scope."""
        self._test_enforcement(request)

    @data(*john_allowed_cases)
    def test_john_library_author_allowed_access(self, request: AuthRequest):
        """Test that John has proper access to his assigned library."""
        self._test_enforcement(request)

    @data(*john_denied_cross_library)
    def test_john_denied_cross_library_access(self, request: AuthRequest):
        """Test that John is denied access to other libraries."""
        self._test_enforcement(request)


@ddt
class LibraryReviewerTests(CasbinEnforcementTestCase):
    """Tests for library reviewer access."""

    sarah_allowed_cases = [
        {
            "subject": "user:sarah",
            "action": "act:read",
            "object": "lib:math-basics",
            "scope": "lib:math-basics",
            "expected_result": True,
        },
    ]

    sarah_denied_cases = [
        {
            "subject": "user:sarah",
            "action": "act:write",
            "object": "lib:math-basics",
            "scope": "lib:math-basics",
            "expected_result": False,
        },
        {
            "subject": "user:sarah",
            "action": "act:edit",
            "object": "lib:math-basics",
            "scope": "lib:math-basics",
            "expected_result": False,
        },
        {
            "subject": "user:sarah",
            "action": "act:delete",
            "object": "lib:math-basics",
            "scope": "lib:math-basics",
            "expected_result": False,
        },
    ]

    @data(*sarah_allowed_cases)
    def test_sarah_library_reviewer_allowed_access(self, request: AuthRequest):
        """Test that Sarah has proper read-only access to her assigned library."""
        self._test_enforcement(request)

    @data(*sarah_denied_cases)
    def test_sarah_denied_higher_privileges(self, request: AuthRequest):
        """Test that Sarah is denied write/edit/delete access."""
        self._test_enforcement(request)


@ddt
class ReportViewerTests(CasbinEnforcementTestCase):
    """Tests for report viewer access."""

    maria_cases = [
        {
            "subject": "user:maria",
            "action": "act:read",
            "object": "report:openedx-usage-2025",
            "scope": "org:OpenedX",
            "expected_result": True,
        },
    ]

    @data(*maria_cases)
    def test_maria_report_viewer_access(self, request: AuthRequest):
        """Test that Maria has proper access to reports in her scope."""
        self._test_enforcement(request)


@ddt
class UnauthorizedUserTests(CasbinEnforcementTestCase):
    """Tests for unauthorized user access."""

    unauthorized_cases = [
        {
            "subject": "user:unknown",
            "action": "act:read",
            "object": "lib:math-basics",
            "scope": "lib:math-basics",
            "expected_result": False,
        },
    ]

    @data(*unauthorized_cases)
    def test_unauthorized_user_denied_access(self, request: AuthRequest):
        """Test that unknown/unauthorized users are denied access."""
        self._test_enforcement(request)
