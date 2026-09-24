"""Unit tests for openedx_authz.rest_api.v1.permissions."""

from unittest.mock import MagicMock, patch

import ddt
from django.test import TestCase

from openedx_authz.rest_api.v1.permissions import (
    BaseScopePermission,
    ContentLibraryPermission,
    CoursePermission,
    DynamicScopePermission,
)


def _make_user(superuser=False):
    """Return a mock user. Regular user by default; pass superuser=True for a superuser."""
    user = MagicMock()
    user.is_superuser = superuser
    user.is_staff = False
    user.username = "testuser"
    return user


def _make_request(data=None, query_params=None, user=None, method="GET"):
    """Return a mock DRF request with the given body data, query params, user, and HTTP method."""
    request = MagicMock()
    request.data = data or {}
    request.query_params = query_params or {}
    request.method = method
    request.user = user or _make_user()
    return request


def _make_view(method="get", required_permissions=None):
    """Return a mock view whose handler carries required_permissions when provided,
    simulating the @authz_permissions decorator. Omit required_permissions to simulate
    a plain handler with no decorator."""
    view = MagicMock()
    handler = MagicMock()
    if required_permissions is not None:
        handler.required_permissions = required_permissions
    else:
        del handler.required_permissions
    setattr(view, method, handler)
    return view


class TestGetScopeValueScopesFallback(TestCase):
    """Test scopes-list fallback in BaseScopePermission.get_scope_value."""

    def setUp(self):
        self.perm = BaseScopePermission()

    def test_scopes_list_fallback_returns_first_element(self):
        """When no 'scope' key is present, the first item of the 'scopes' list is used as the scope value."""
        request = _make_request(data={"scopes": ["lib:Org:A", "lib:Org:B"]})
        self.assertEqual(self.perm.get_scope_value(request), "lib:Org:A")

    def test_scope_is_string_returns_value(self):
        """When 'scope' is a plain string instead of a list, it is used as scope value."""
        request = _make_request(data={"scope": "lib:Org:A"})
        self.assertEqual(self.perm.get_scope_value(request), "lib:Org:A")


class TestGetScopeNamespaceMixedScopes(TestCase):
    """Test that get_scope_namespace enforces namespace homogeneity for bulk scopes."""

    def setUp(self):
        self.perm = BaseScopePermission()

    def test_mixed_namespaces_raises_value_error(self):
        """Passing scopes from different namespaces in a single bulk request raises ValueError."""
        request = _make_request(data={"scopes": ["lib:Org:A", "course-v1:Org1+C1+2024"]})
        with self.assertRaises(ValueError):
            self.perm.get_scope_namespace(request)

    def test_homogeneous_namespaces_does_not_raise(self):
        """Passing scopes that all share the same namespace does not raise."""
        request = _make_request(data={"scopes": ["lib:Org:A", "lib:Org:B"]})
        # Should not raise — just verify it completes without error
        namespace = self.perm.get_scope_namespace(request)
        self.assertEqual(namespace, "lib")


class TestDynamicScopePermissionBulkScopes(TestCase):
    """Test bulk-scopes path in DynamicScopePermission.has_permission."""

    def setUp(self):
        self.perm = DynamicScopePermission()

    def test_non_mixin_namespace_returns_false(self):
        """A 'global' scope resolves to BaseScopePermission which does not implement MethodPermissionMixin.
        The bulk path requires MethodPermissionMixin, so the check is rejected immediately."""
        request = _make_request(data={"scopes": ["global:x"]})
        self.assertFalse(self.perm.has_permission(request, _make_view(required_permissions=["p"])))

    def test_no_required_permissions_returns_false(self):
        """When the view method has no @authz_permissions decorator, there are no required permissions
        to evaluate, so the bulk check is rejected."""
        request = _make_request(data={"scopes": ["lib:Org:A", "lib:Org:B"]})
        self.assertFalse(self.perm.has_permission(request, _make_view(required_permissions=None)))

    @patch("openedx_authz.api.is_user_allowed", return_value=True)
    def test_all_scopes_pass_returns_true(self, _):
        """When the user has the required permission on every scope in the list, access is granted
        (AND logic across scopes — all must pass)."""
        request = _make_request(data={"scopes": ["lib:Org:A", "lib:Org:B"]}, method="GET")
        self.assertTrue(self.perm.has_permission(request, _make_view(method="get", required_permissions=["p"])))

    @patch("openedx_authz.api.is_user_allowed", side_effect=[True, False])
    def test_one_scope_fails_returns_false(self, _):
        """When the user lacks the required permission on at least one scope, access is denied
        (AND logic across scopes — a single failure is enough to reject)."""
        request = _make_request(data={"scopes": ["lib:Org:A", "lib:Org:B"]}, method="GET")
        self.assertFalse(self.perm.has_permission(request, _make_view(method="get", required_permissions=["p"])))


@ddt.ddt
class TestDynamicScopePermissionBulkScopesMixed(TestCase):
    """Test DynamicScopePermission bulk-scopes behaviour when mixing specific and org-level scopes.

    Parameterized over lib (lib:Org:A / lib:Org:*) and course-v1 (course-v1:Org1+C1+2024 / course-v1:Org1+*)
    namespaces to verify that the AND-logic holds regardless of whether a scope targets a specific
    resource or an entire org.
    """

    def setUp(self):
        self.perm = DynamicScopePermission()

    def test_mixed_namespaces_raises_value_error(self):
        """Mixing lib and course-v1 scopes in the same bulk request raises ValueError."""
        request = _make_request(data={"scopes": ["lib:Org:A", "course-v1:Org1+C1+2024"]})
        with self.assertRaises(ValueError):
            self.perm.has_permission(request, _make_view(required_permissions=["p"]))

    @ddt.data(
        (["lib:Org:A", "lib:Org:*"], "get"),
        (["course-v1:Org1+C1+2024", "course-v1:Org1+*"], "get"),
    )
    @ddt.unpack
    @patch("openedx_authz.api.is_user_allowed", return_value=True)
    def test_specific_and_org_scope_both_pass_returns_true(self, scopes, method, _):
        """When the user has permission on both the specific scope and the org-level scope, access is granted."""
        request = _make_request(data={"scopes": scopes}, method=method.upper())
        self.assertTrue(self.perm.has_permission(request, _make_view(method=method, required_permissions=["p"])))

    @ddt.data(
        (["lib:Org:A", "lib:Org:*"], "get"),
        (["course-v1:Org1+C1+2024", "course-v1:Org1+*"], "get"),
    )
    @ddt.unpack
    @patch("openedx_authz.api.is_user_allowed", side_effect=[True, False])
    def test_specific_passes_org_fails_returns_false(self, scopes, method, _):
        """When the user has permission on the specific scope but not the org-level scope, access is denied."""
        request = _make_request(data={"scopes": scopes}, method=method.upper())
        self.assertFalse(self.perm.has_permission(request, _make_view(method=method, required_permissions=["p"])))

    @ddt.data(
        (["lib:Org:A", "lib:Org:*"], "get"),
        (["course-v1:Org1+C1+2024", "course-v1:Org1+*"], "get"),
    )
    @ddt.unpack
    @patch("openedx_authz.api.is_user_allowed", side_effect=[False, True])
    def test_specific_fails_org_passes_returns_false(self, scopes, method, _):
        """When the user has permission on the org-level scope but not the specific scope, access is denied."""
        request = _make_request(data={"scopes": scopes}, method=method.upper())
        self.assertFalse(self.perm.has_permission(request, _make_view(method=method, required_permissions=["p"])))


class TestCoursePermission(TestCase):
    """Test CoursePermission class."""

    def setUp(self):
        self.perm = CoursePermission()

    def test_no_scope_returns_false(self):
        """A request without any scope value is always rejected — there is nothing to authorize against."""
        self.assertFalse(self.perm.has_permission(_make_request(), _make_view(required_permissions=["p"])))

    def test_scope_no_decorator_returns_true(self):
        """When a scope is present but the view method has no @authz_permissions decorator,
        the endpoint is considered open and access is granted."""
        request = _make_request(data={"scope": "course-v1:Org1+C1+2024"})
        self.assertTrue(self.perm.has_permission(request, _make_view(required_permissions=None)))

    @patch("openedx_authz.api.is_user_allowed", return_value=True)
    def test_scope_with_permission_allowed(self, _):
        """When the user has the required permission on the given course scope, access is granted."""
        request = _make_request(data={"scope": "course-v1:Org1+C1+2024"}, method="GET")
        self.assertTrue(self.perm.has_permission(request, _make_view(method="get", required_permissions=["p"])))

    @patch("openedx_authz.api.is_user_allowed", return_value=False)
    def test_scope_with_permission_denied(self, _):
        """When the user lacks the required permission on the course scope, access is denied."""
        request = _make_request(data={"scope": "course-v1:Org1+C1+2024"}, method="GET")
        self.assertFalse(self.perm.has_permission(request, _make_view(method="get", required_permissions=["p"])))

    @patch("openedx_authz.api.is_user_allowed", return_value=True)
    def test_org_scope_allowed(self, _):
        """An org-level course scope ('course-v1:Org1+*') grants access when the user has the required permission."""
        request = _make_request(data={"scope": "course-v1:Org1+*"}, method="GET")
        self.assertTrue(self.perm.has_permission(request, _make_view(method="get", required_permissions=["p"])))

    @patch("openedx_authz.api.is_user_allowed", return_value=False)
    def test_org_scope_denied(self, _):
        """An org-level course scope ('course-v1:Org1+*') denies access when the user lacks the required permission."""
        request = _make_request(data={"scope": "course-v1:Org1+*"}, method="GET")
        self.assertFalse(self.perm.has_permission(request, _make_view(method="get", required_permissions=["p"])))


class TestContentLibraryPermission(TestCase):
    """Test ContentLibraryPermission class."""

    def setUp(self):
        self.perm = ContentLibraryPermission()

    def test_no_scope_returns_false(self):
        """A request without any scope value is always rejected — there is nothing to authorize against."""
        self.assertFalse(self.perm.has_permission(_make_request(), _make_view(required_permissions=["p"])))

    def test_scope_no_decorator_returns_true(self):
        """When a scope is present but the view method has no @authz_permissions decorator,
        the endpoint is considered open and access is granted."""
        request = _make_request(data={"scope": "lib:Org1:A"})
        self.assertTrue(self.perm.has_permission(request, _make_view(required_permissions=None)))

    @patch("openedx_authz.api.is_user_allowed", return_value=True)
    def test_scope_with_permission_allowed(self, _):
        """When the user has the required permission on the given library scope, access is granted."""
        request = _make_request(data={"scope": "lib:Org1:A"}, method="GET")
        self.assertTrue(self.perm.has_permission(request, _make_view(method="get", required_permissions=["p"])))

    @patch("openedx_authz.api.is_user_allowed", return_value=False)
    def test_scope_with_permission_denied(self, _):
        """When the user lacks the required permission on the library scope, access is denied."""
        request = _make_request(data={"scope": "lib:Org1:A"}, method="GET")
        self.assertFalse(self.perm.has_permission(request, _make_view(method="get", required_permissions=["p"])))

    @patch("openedx_authz.api.is_user_allowed", return_value=True)
    def test_org_scope_allowed(self, _):
        """An org-level lib scope ('lib:Org1:*') grants access when the user has the required permission."""
        request = _make_request(data={"scope": "lib:Org1:*"}, method="GET")
        self.assertTrue(self.perm.has_permission(request, _make_view(method="get", required_permissions=["p"])))

    @patch("openedx_authz.api.is_user_allowed", return_value=False)
    def test_org_scope_denied(self, _):
        """An org-level lib scope ('lib:Org1:*') denies access when the user lacks the required permission."""
        request = _make_request(data={"scope": "lib:Org1:*"}, method="GET")
        self.assertFalse(self.perm.has_permission(request, _make_view(method="get", required_permissions=["p"])))
