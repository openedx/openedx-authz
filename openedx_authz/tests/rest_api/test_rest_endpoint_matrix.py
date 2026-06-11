"""
REST API security matrix

Builds an HTTP-level fixture and exercises every endpoint against a table of
expected status codes, data isolation guarantees, and permission-boundary
assertions.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from django.contrib.auth import get_user_model
from django.urls import reverse
from organizations.models import Organization
from rest_framework import status
from rest_framework.test import APIClient

from openedx_authz.api.users import assign_role_to_user_in_scope
from openedx_authz.constants import permissions, roles
from openedx_authz.rest_api.v1.permissions import DynamicScopePermission
from openedx_authz.tests.api.test_roles import BaseRolesTestCase

User = get_user_model()

# Persona names
P_NOBODY = "nobody"
P_LIB_ADMIN = "lib_admin"  # library_admin on LIB_OWN
P_COURSE_ADMIN = "course_admin"  # course_admin  on COURSE_OWN
P_ORG_LIB_ADMIN = "org_lib_admin"  # library_admin on lib:OrgA:* (org-glob)
P_STAFF = "staff"  # Django is_staff=True, no authz assignments
P_SUPERUSER = "superuser"  # Django is_superuser=True, no authz assignments

# Scopes
LIB_OWN = "lib:OrgA:LibX"
LIB_OTHER_ORG = "lib:OrgB:LibZ"
COURSE_OWN = "course-v1:OrgA+CourseA+2024"
ORG_LIB_GLOB = "lib:OrgA:*"

# Orgs for cross-org disclosure test
ORG_A = "OrgA"
ORG_B = "OrgB"


# URL helpers
URL_PERM_VALIDATE = reverse("openedx_authz:permission-validation-me")
URL_ROLE_LIST = reverse("openedx_authz:role-list")
URL_ROLE_USERS = reverse("openedx_authz:role-user-list")
URL_ORGS = reverse("openedx_authz:orgs-list")
URL_USERS = reverse("openedx_authz:user-list")
URL_USER_VALIDATE = reverse("openedx_authz:user-validation")
URL_ASSIGNMENTS = reverse("openedx_authz:assignment-list")
URL_SCOPES = reverse("openedx_authz:scope-list")


def _url_user_assignments(username: str) -> str:
    return reverse("openedx_authz:user-assignment-list", kwargs={"username": username})


# Fixture base class
class SharedFixture(BaseRolesTestCase):
    """
    Shared fixture: six personas, two scopes, two orgs.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # Create Django Users (must happen before Casbin assignments so
        # get_superadmin_assignments can find staff/superuser rows).
        _plain = {"defaults": {"email": "placeholder@test.example"}}
        for username in (P_NOBODY, P_LIB_ADMIN, P_COURSE_ADMIN, P_ORG_LIB_ADMIN):
            User.objects.get_or_create(
                username=username,
                defaults={"email": f"{username}@test.example"},
            )
        User.objects.get_or_create(
            username=P_STAFF,
            defaults={"email": "p5_staff@test.example", "is_staff": True},
        )
        User.objects.get_or_create(
            username=P_SUPERUSER,
            defaults={"email": "p5_superuser@test.example", "is_superuser": True},
        )

        # Orgs - needed for cross-org disclosure assertion.
        Organization.objects.get_or_create(name=ORG_A, short_name=ORG_A, defaults={"active": True})
        Organization.objects.get_or_create(name=ORG_B, short_name=ORG_B, defaults={"active": True})

        # Casbin assignments (UserData / "user^" namespace)
        assign_role_to_user_in_scope(P_LIB_ADMIN, roles.LIBRARY_ADMIN.external_key, LIB_OWN)
        assign_role_to_user_in_scope(P_COURSE_ADMIN, roles.COURSE_ADMIN.external_key, COURSE_OWN)
        assign_role_to_user_in_scope(P_ORG_LIB_ADMIN, roles.LIBRARY_ADMIN.external_key, ORG_LIB_GLOB)

    def setUp(self):
        super().setUp()
        self.client = APIClient()

    def _auth_as(self, username: str) -> User:
        user = User.objects.get(username=username)
        self.client.force_authenticate(user=user)
        return user

    def _anon(self):
        self.client.force_authenticate(user=None)


# Group 1 - Authentication gate: every endpoint requires authentication
class TestAuthGates(SharedFixture):
    """All endpoints return 401 for unauthenticated requests."""

    def _assert_401(self, method: str, url: str, **kwargs):
        self._anon()
        response = getattr(self.client, method)(url, **kwargs)
        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
            msg=f"Expected 401 on {method.upper()} {url} for anonymous user, got {response.status_code}",
        )

    def test_permission_validation_me_requires_auth(self):
        self._assert_401(
            "post",
            URL_PERM_VALIDATE,
            data=[{"action": permissions.VIEW_LIBRARY.identifier, "scope": LIB_OWN}],
            format="json",
        )

    def test_role_list_requires_auth(self):
        self._assert_401("get", URL_ROLE_LIST, data={"scope": LIB_OWN})

    def test_role_users_get_requires_auth(self):
        self._assert_401("get", URL_ROLE_USERS, data={"scope": LIB_OWN})

    def test_role_users_put_requires_auth(self):
        self._assert_401(
            "put",
            URL_ROLE_USERS,
            data={"scope": LIB_OWN, "role": roles.LIBRARY_ADMIN.external_key, "users": ["someuser"]},
            format="json",
        )

    def test_role_users_delete_requires_auth(self):
        self._assert_401(
            "delete",
            URL_ROLE_USERS + f"?scope={LIB_OWN}&role={roles.LIBRARY_ADMIN.external_key}&users=someuser",
        )

    def test_orgs_requires_auth(self):
        self._assert_401("get", URL_ORGS)

    def test_users_requires_auth(self):
        self._assert_401("get", URL_USERS)

    def test_user_validate_requires_auth(self):
        self._assert_401("post", URL_USER_VALIDATE, data={"users": ["any"]}, format="json")

    def test_user_assignments_requires_auth(self):
        self._assert_401("get", _url_user_assignments(P_LIB_ADMIN))

    def test_assignments_requires_auth(self):
        self._assert_401("get", URL_ASSIGNMENTS)

    def test_scopes_requires_auth(self):
        self._assert_401("get", URL_SCOPES)


# Group 2 - Namespace isolation: lib assignments do not grant access to
# course endpoints, and vice versa.
class TestNamespaceIsolation(SharedFixture):
    """
    Assignments in one namespace must not grant access across namespaces.
    """

    def test_lib_admin_denied_role_list_on_course_scope(self):
        """
        A library admin cannot list roles for a course scope.
        """
        self._auth_as(P_LIB_ADMIN)
        response = self.client.get(URL_ROLE_LIST, data={"scope": COURSE_OWN})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_lib_admin_denied_role_users_get_on_course_scope(self):
        """
        A library admin cannot list team members for a course scope.
        """
        self._auth_as(P_LIB_ADMIN)
        response = self.client.get(URL_ROLE_USERS, data={"scope": COURSE_OWN})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_lib_admin_denied_role_users_put_on_course_scope(self):
        """
        A library admin cannot assign roles on a course scope.
        """
        self._auth_as(P_LIB_ADMIN)
        response = self.client.put(
            URL_ROLE_USERS,
            data={"scope": COURSE_OWN, "role": roles.COURSE_ADMIN.external_key, "users": ["x"]},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_course_admin_denied_role_list_on_lib_scope(self):
        """
        A course admin cannot list roles for a library scope.
        """
        self._auth_as(P_COURSE_ADMIN)
        response = self.client.get(URL_ROLE_LIST, data={"scope": LIB_OWN})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_course_admin_denied_role_users_put_on_lib_scope(self):
        """
        A course admin cannot assign library roles.
        """
        self._auth_as(P_COURSE_ADMIN)
        response = self.client.put(
            URL_ROLE_USERS,
            data={"scope": LIB_OWN, "role": roles.LIBRARY_ADMIN.external_key, "users": ["x"]},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


# Group 3 - Org-scope isolation: exact-scope assignment does not bleed
# across orgs.
class TestOrgScopeIsolation(SharedFixture):
    """
    A user with an exact-scope assignment cannot access other-org scopes.
    """

    def test_lib_admin_denied_role_list_on_other_org_lib(self):
        """
        lib_admin (assigned to OrgA:LibX) cannot list roles for OrgB:LibZ.
        """
        self._auth_as(P_LIB_ADMIN)
        response = self.client.get(URL_ROLE_LIST, data={"scope": LIB_OTHER_ORG})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_lib_admin_denied_role_users_put_on_other_org_lib(self):
        """
        lib_admin (assigned to OrgA:LibX) cannot assign roles in OrgB:LibZ.
        """
        self._auth_as(P_LIB_ADMIN)
        response = self.client.put(
            URL_ROLE_USERS,
            data={"scope": LIB_OTHER_ORG, "role": roles.LIBRARY_ADMIN.external_key, "users": ["x"]},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


# Group 4 - null-user bypass not reachable via REST.
class TestF007NullUserBypassClosure(SharedFixture):
    """
    The null-user bypass in _filter_allowed_assignments is not reachable via REST.

    All three call sites in views.py (TeamMembersAPIView, AssignmentsAPIView,
    TeamMemberAssignmentsAPIView) pass ``allowed_for_user_external_key=
    request.user.username``.  Since request.user is always an authenticated User
    object, username is never None.  These tests confirm that each call site
    returns a filtered (not all-or-nothing) view of the data.
    """

    def test_users_endpoint_filters_by_caller_scope(self):
        """
        GET /users/ returns results filtered to the caller's view_team scopes.

        lib_admin only has view_library_team on LIB_OWN.  The list of team
        members should be non-empty (includes users assigned to LIB_OWN) yet
        should NOT include users assigned exclusively to COURSE_OWN (different
        namespace, no view permission).
        """
        self._auth_as(P_LIB_ADMIN)
        response = self.client.get(URL_USERS)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # The response is filtered - count is determined by the caller's
        # permissions, not by total assignments in the system.
        # (We just assert it succeeds and does not return everything including
        # P_COURSE_ADMIN's course assignments.)
        usernames_returned = {m["username"] for m in response.data["results"]}
        # course_admin is assigned only to COURSE_OWN, lib_admin has no
        # view_team on course scopes, so course_admin should not appear.
        self.assertNotIn(
            P_COURSE_ADMIN,
            usernames_returned,
            msg="lib_admin must not see users in course scopes (cross-namespace leakage).",
        )

    def test_assignments_endpoint_filters_by_caller_scope(self):
        """
        GET /assignments/ returns assignments filtered to the caller's view_team scopes.
        """
        self._auth_as(P_LIB_ADMIN)
        response = self.client.get(URL_ASSIGNMENTS)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        scopes_in_response = {a["scope"] for a in response.data["results"] if not a["is_superadmin"]}
        # lib_admin has no view_team on course scopes, course assignments must
        # not appear.
        course_scopes = {s for s in scopes_in_response if s.startswith("course-v1:")}
        self.assertEqual(
            course_scopes,
            set(),
            msg="lib_admin must not see course-scoped assignments.",
        )

    def test_user_assignments_endpoint_filters_by_caller_scope(self):
        """
        GET /users/<username>/assignments/ filters regular assignments by caller's scope.

        The caller (lib_admin) has view_library_team on LIB_OWN.  Querying for
        course_admin's assignments should return no regular (non-superadmin)
        assignments, because lib_admin cannot see course-scoped assignments.
        """
        self._auth_as(P_LIB_ADMIN)
        response = self.client.get(_url_user_assignments(P_COURSE_ADMIN))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        regular_assignments = [a for a in response.data["results"] if not a["is_superadmin"]]
        for assignment in regular_assignments:
            self.assertFalse(
                assignment["scope"].startswith("course-v1:"),
                msg="lib_admin must not see course-scoped assignments for another user.",
            )


# Group 5 - mixed-namespace bulk scopes list in  ``PUT /roles/users/``
# causes an unhandled ValueError.
class TestMixedNamespaceBulkPut(SharedFixture):
    """
    Mixed-namespace ``scopes`` list in PUT causes unhandled ValueError.

    This is an open issue, we should return 403 instead of propagating.
    """

    def test_mixed_namespace_scope_list_raises_value_error(self):
        """
        DynamicScopePermission.has_permission raises ValueError for mixed-namespace
        ``scopes`` lists instead of returning False.

        In production, this ValueError propagates through DRF's exception handler
        (which only handles APIException subclasses) and reaches Django's WSGI
        handler, resulting in a 500 Internal Server Error.

        The correct behaviour is to return False (yielding 403) or raise a
        proper 400 ValidationError.
        """
        perm = DynamicScopePermission()
        user = MagicMock()
        user.is_superuser = False
        user.is_staff = False
        user.username = P_LIB_ADMIN

        request = MagicMock()
        request.user = user
        request.data = {"scopes": [LIB_OWN, COURSE_OWN], "role": "library_admin", "users": ["x"]}

        view = MagicMock()
        get_handler = MagicMock()
        get_handler.required_permissions = [
            permissions.MANAGE_LIBRARY_TEAM.identifier,
            permissions.COURSES_MANAGE_COURSE_TEAM.identifier,
        ]
        view.put = get_handler
        request.method = "PUT"

        with self.assertRaises(ValueError, msg="Mixed-namespace bulk PUT must raise ValueError"):
            perm.has_permission(request, view)

    def test_single_namespace_bulk_put_does_not_raise(self):
        """
        A bulk PUT with a homogeneous namespace list (all lib) does NOT raise.

        This is the control case: confirms the ValueError only fires for
        mixed-namespace requests, not for legitimate bulk-lib or bulk-course
        requests.
        """
        perm = DynamicScopePermission()
        user = MagicMock()
        user.is_superuser = False
        user.is_staff = False
        user.username = P_LIB_ADMIN

        request = MagicMock()
        request.user = user
        request.data = {"scopes": [LIB_OWN, "lib:OrgA:LibY"], "role": "library_admin", "users": ["x"]}

        view = MagicMock()
        put_handler = MagicMock()
        put_handler.required_permissions = [
            permissions.MANAGE_LIBRARY_TEAM.identifier,
            permissions.COURSES_MANAGE_COURSE_TEAM.identifier,
        ]
        view.put = put_handler
        request.method = "PUT"

        # Must NOT raise - homogeneous namespace should be handled gracefully
        try:
            perm.has_permission(request, view)
        except ValueError as exc:
            self.fail(f"Homogeneous-namespace bulk PUT raised unexpected ValueError: {exc}")


# Group 6: superadmin status discoverable by any team admin via
# /users/<username>/assignments/.
class TestSuperadminEnumeration(SharedFixture):
    """
    Any team admin can enumerate superadmin status for arbitrary users.

    ``get_superadmin_assignments(user_external_keys=[username])`` is called with
    no permission filter beyond the outer AnyScopePermission gate.  A caller
    who has view_library_team on a completely unrelated scope can discover
    whether any user is a Django staff/superuser.

    This is a design decision for display purposes in the admin console, if this
    test is failing we should be aware of that and update the frontend logic.
    """

    def test_lib_admin_can_discover_superuser_status_of_unrelated_user(self):
        """
        A library admin who shares NO scope with the target user can discover
        that the target is a Django superuser.

        lib_admin has view_library_team only on lib:OrgA:LibX.
        superuser has NO authz assignments at all.
        The endpoint still returns is_superadmin=True for superuser.
        """
        self._auth_as(P_LIB_ADMIN)
        response = self.client.get(_url_user_assignments(P_SUPERUSER))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        superadmin_entries = [r for r in response.data["results"] if r["is_superadmin"]]
        self.assertGreater(
            len(superadmin_entries),
            0,
            msg=(
                "lib_admin can discover superadmin status of an unrelated user "
                "via /users/<username>/assignments/ - no scope-level check on "
                "get_superadmin_assignments()."
            ),
        )

    def test_lib_admin_can_discover_staff_status_of_unrelated_user(self):
        """
        Same behavior for Django staff (not superuser).
        """
        self._auth_as(P_LIB_ADMIN)
        response = self.client.get(_url_user_assignments(P_STAFF))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        superadmin_entries = [r for r in response.data["results"] if r["is_superadmin"]]
        self.assertGreater(
            len(superadmin_entries),
            0,
            msg=("lib_admin can discover staff status of an unrelated user."),
        )

    def test_nobody_cannot_probe_superadmin_status(self):
        """
        A user with NO view_team permission anywhere is denied the endpoint.

        The outer AnyScopePermission gate prevents access, the expectation
        only matters for users who have at least one valid scope-level
        permission.
        """
        self._auth_as(P_NOBODY)
        response = self.client.get(_url_user_assignments(P_SUPERUSER))
        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
            msg="Nobody should be denied /users/<username>/assignments/.",
        )


# Group 7 - REST level: /orgs/ discloses all active orgs to any
# single-scope team admin.
class TestF003OrgsDisclosureREST(SharedFixture):
    """
    GET /orgs/ returns all active orgs to any team admin.

    A user who only has view_library_team on lib:OrgA:LibX can still query
    /orgs/ and receive every active organisation, including OrgB.

    If these tests start failing we should be make sure that the
    behavior change doesn't break anything on the frontend.
    """

    def test_lib_admin_sees_all_active_orgs(self):
        """
        lib_admin (scoped to OrgA only) receives OrgB from GET /orgs/.

        The endpoint has no org-scope filtering - it returns all active
        organizations to any caller who passes the AnyScopePermission gate.
        """
        self._auth_as(P_LIB_ADMIN)
        response = self.client.get(URL_ORGS)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        short_names = {org["short_name"] for org in response.data["results"]}
        self.assertIn(ORG_B, short_names, msg="lib_admin (OrgA-scoped) can see OrgB via GET /orgs/.")
        self.assertIn(ORG_A, short_names)

    def test_f003_nobody_cannot_see_orgs(self):
        """A user with no permissions at all is denied GET /orgs/."""
        self._auth_as(P_NOBODY)
        response = self.client.get(URL_ORGS)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


# Group 8 - PermissionValidationMeView isolation: the permission-check
# endpoint always operates on request.user, not an attacker-supplied user.
class TestPermissionValidationSelfOnly(SharedFixture):
    """
    POST /permissions/validate/me always checks the authenticated user's permissions.
    """

    def test_cannot_check_another_users_permissions(self):
        """
        The endpoint uses request.user.username unconditionally.

        An authenticated nobody cannot obtain True by checking permissions
        on behalf of a lib_admin - the check is always for the requesting user.
        """
        self._auth_as(P_NOBODY)
        # Check a permission that lib_admin has but nobody does not.
        response = self.client.post(
            URL_PERM_VALIDATE,
            data=[{"action": permissions.VIEW_LIBRARY.identifier, "scope": LIB_OWN}],
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data[0]["allowed"], False, msg="Nobody must not be allowed view_library on LIB_OWN.")

    def test_lib_admin_allowed_on_own_scope(self):
        """
        lib_admin gets allowed=True for view_library on LIB_OWN.
        """
        self._auth_as(P_LIB_ADMIN)
        response = self.client.post(
            URL_PERM_VALIDATE,
            data=[{"action": permissions.VIEW_LIBRARY.identifier, "scope": LIB_OWN}],
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data[0]["allowed"], True)

    def test_unknown_scope_returns_400(self):
        """
        A scope string with an unknown namespace returns 400 (not 500).
        """
        self._auth_as(P_LIB_ADMIN)
        response = self.client.post(
            URL_PERM_VALIDATE,
            data=[{"action": permissions.VIEW_LIBRARY.identifier, "scope": "nosuchns:anything"}],
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
