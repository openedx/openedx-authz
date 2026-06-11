"""
Tests to guard against privilege escalation and behavior changes in the
internal API.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model

from openedx_authz.api.data import (
    RoleData,
    ScopeData,
    UserData,
)
from openedx_authz.api.roles import (
    assign_role_to_subject_in_scope,
    get_scopes_for_subject_and_permission,
    get_subject_role_assignments,
)
from openedx_authz.api.users import (
    get_superadmin_assignments,
    get_visible_role_assignments_for_user,
    is_user_allowed,
)
from openedx_authz.constants import permissions, roles
from openedx_authz.tests.api.test_roles import BaseRolesTestCase

User = get_user_model()


# Library scopes
LIB_OWN = "lib:OrgA:LibX"  # lib_admin's assigned scope
LIB_SAME_ORG = "lib:OrgA:LibY"  # same org, different library
LIB_DIFF_ORG = "lib:OrgB:LibZ"  # entirely different org

# Course scopes
COURSE_OWN = "course-v1:OrgA+CourseA+2024"  # course_admin's scope
COURSE_SAME_ORG = "course-v1:OrgA+CourseB+2024"  # same org, different course
COURSE_DIFF_ORG = "course-v1:OrgB+CourseC+2024"  # different org

# Glob scopes used in assignments
ORG_LIB_GLOB = "lib:OrgA:*"
PLATFORM_COURSE_GLOB = "course-v1:*"

# Persona usernames
P_NOBODY = "nobody"
P_LIB_ADMIN = "lib_admin"
P_COURSE_ADMIN = "course_admin"
P_ORG_LIB_ADMIN = "org_lib_admin"
P_PLATFORM_COURSE_ADMIN = "platform_course_admin"
P_STAFF = "django_staff"

# Seed users for disclosure gate tests
SEED_LIB_USER = "seed_lib"  # library_admin on LIB_OWN
SEED_COURSE_USER = "seed_course"  # course_admin on COURSE_OWN
SEED_OTHER_ORG_LIB = "seed_other_org_lib"  # library_admin on LIB_DIFF_ORG


class RoleFixture(BaseRolesTestCase):
    """
    Shared fixture for test classes.

    Creates:
    - Django User objects for every persona + seed user
    - Casbin role assignments using ``UserData``
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        for username in (
            P_NOBODY,
            P_LIB_ADMIN,
            P_COURSE_ADMIN,
            P_ORG_LIB_ADMIN,
            P_PLATFORM_COURSE_ADMIN,
            SEED_LIB_USER,
            SEED_COURSE_USER,
            SEED_OTHER_ORG_LIB,
        ):
            User.objects.get_or_create(
                username=username,
                defaults={"email": f"{username}@example.com"},
            )
        User.objects.get_or_create(
            username=P_STAFF,
            defaults={"email": f"{P_STAFF}@example.com", "is_staff": True},
        )

        def _assign(username, role_key, scope_key):
            assign_role_to_subject_in_scope(
                subject=UserData(external_key=username),
                role=RoleData(external_key=role_key),
                scope=ScopeData(external_key=scope_key),
            )

        _assign(P_LIB_ADMIN, roles.LIBRARY_ADMIN.external_key, LIB_OWN)
        _assign(P_COURSE_ADMIN, roles.COURSE_ADMIN.external_key, COURSE_OWN)
        _assign(P_ORG_LIB_ADMIN, roles.LIBRARY_ADMIN.external_key, ORG_LIB_GLOB)
        _assign(P_PLATFORM_COURSE_ADMIN, roles.COURSE_ADMIN.external_key, PLATFORM_COURSE_GLOB)
        # Django staff user intentionally has no authz assignments

        # Seed users for disclosure-gate probing
        _assign(SEED_LIB_USER, roles.LIBRARY_ADMIN.external_key, LIB_OWN)
        _assign(SEED_COURSE_USER, roles.COURSE_ADMIN.external_key, COURSE_OWN)
        _assign(SEED_OTHER_ORG_LIB, roles.LIBRARY_ADMIN.external_key, LIB_DIFF_ORG)


# Convenience permission identifier strings
_VIEW_LIB = permissions.VIEW_LIBRARY.action.external_key
_DELETE_LIB = permissions.DELETE_LIBRARY.action.external_key
_VIEW_LIB_TM = permissions.VIEW_LIBRARY_TEAM.action.external_key
_VIEW_COURSE = permissions.COURSES_VIEW_COURSE.action.external_key


class TestIsUserAllowedTruthTable(RoleFixture):
    """
    Check expected results for is_user_allowed.
    """

    #  nobody
    def test_nobody_denied_on_library(self):
        self.assertFalse(is_user_allowed(P_NOBODY, _VIEW_LIB, LIB_OWN))

    def test_nobody_denied_on_course(self):
        self.assertFalse(is_user_allowed(P_NOBODY, _VIEW_COURSE, COURSE_OWN))

    #  lib_admin: own scope grants, other scopes deny
    def test_lib_admin_allowed_view_on_own_lib(self):
        self.assertTrue(is_user_allowed(P_LIB_ADMIN, _VIEW_LIB, LIB_OWN))

    def test_lib_admin_allowed_delete_on_own_lib(self):
        self.assertTrue(is_user_allowed(P_LIB_ADMIN, _DELETE_LIB, LIB_OWN))

    def test_lib_admin_allowed_view_team_on_own_lib(self):
        self.assertTrue(is_user_allowed(P_LIB_ADMIN, _VIEW_LIB_TM, LIB_OWN))

    def test_lib_admin_denied_on_same_org_different_lib(self):
        """
        Scope isolation: lib admin on LibX must be denied for LibY.
        """
        self.assertFalse(is_user_allowed(P_LIB_ADMIN, _VIEW_LIB, LIB_SAME_ORG))

    def test_lib_admin_denied_on_different_org_lib(self):
        self.assertFalse(is_user_allowed(P_LIB_ADMIN, _VIEW_LIB, LIB_DIFF_ORG))

    def test_lib_admin_denied_on_course_same_org(self):
        """
        Namespace isolation: library assignment must not bleed to courses.
        """
        self.assertFalse(is_user_allowed(P_LIB_ADMIN, _VIEW_COURSE, COURSE_OWN))

    def test_lib_admin_denied_on_course_diff_org(self):
        self.assertFalse(is_user_allowed(P_LIB_ADMIN, _VIEW_COURSE, COURSE_DIFF_ORG))

    #  course_admin: own scope grants, other scopes deny
    def test_course_admin_allowed_view_on_own_course(self):
        self.assertTrue(is_user_allowed(P_COURSE_ADMIN, _VIEW_COURSE, COURSE_OWN))

    def test_course_admin_denied_on_same_org_different_course(self):
        """
        Scope isolation: course admin on CourseA must be denied for CourseB.
        """
        self.assertFalse(is_user_allowed(P_COURSE_ADMIN, _VIEW_COURSE, COURSE_SAME_ORG))

    def test_course_admin_denied_on_different_org_course(self):
        self.assertFalse(is_user_allowed(P_COURSE_ADMIN, _VIEW_COURSE, COURSE_DIFF_ORG))

    def test_course_admin_denied_on_library_same_org(self):
        """
        Namespace isolation: course assignment must not bleed to libraries.
        """
        self.assertFalse(is_user_allowed(P_COURSE_ADMIN, _VIEW_LIB, LIB_OWN))

    def test_course_admin_denied_on_library_diff_org(self):
        self.assertFalse(is_user_allowed(P_COURSE_ADMIN, _VIEW_LIB, LIB_DIFF_ORG))

    #  org_lib_admin: org glob covers all OrgA libs, not OrgB, not courses
    def test_org_lib_admin_allowed_on_own_org_lib_x(self):
        self.assertTrue(is_user_allowed(P_ORG_LIB_ADMIN, _VIEW_LIB, LIB_OWN))

    def test_org_lib_admin_allowed_on_own_org_lib_y(self):
        """
        Org glob must cover all libraries in OrgA, not just the assigned one.
        """
        self.assertTrue(is_user_allowed(P_ORG_LIB_ADMIN, _VIEW_LIB, LIB_SAME_ORG))

    def test_org_lib_admin_denied_on_different_org_lib(self):
        """
        Org isolation: lib:OrgA:* must not match lib:OrgB:*.
        """
        self.assertFalse(is_user_allowed(P_ORG_LIB_ADMIN, _VIEW_LIB, LIB_DIFF_ORG))

    def test_org_lib_admin_denied_on_course(self):
        """
        Namespace isolation: org lib glob must not bleed into courses.
        """
        self.assertFalse(is_user_allowed(P_ORG_LIB_ADMIN, _VIEW_COURSE, COURSE_OWN))

    def test_org_lib_admin_denied_on_course_same_org(self):
        self.assertFalse(is_user_allowed(P_ORG_LIB_ADMIN, _VIEW_COURSE, COURSE_SAME_ORG))

    #  platform_course_admin: platform glob covers ALL courses
    def test_platform_course_admin_allowed_on_own_course(self):
        self.assertTrue(is_user_allowed(P_PLATFORM_COURSE_ADMIN, _VIEW_COURSE, COURSE_OWN))

    def test_platform_course_admin_allowed_on_same_org_other_course(self):
        """
        Platform glob must cover courses in the same org beyond the base scope.
        """
        self.assertTrue(is_user_allowed(P_PLATFORM_COURSE_ADMIN, _VIEW_COURSE, COURSE_SAME_ORG))

    def test_platform_course_admin_allowed_on_different_org_course(self):
        """
        Platform glob must cover every course, including other orgs.
        """
        self.assertTrue(is_user_allowed(P_PLATFORM_COURSE_ADMIN, _VIEW_COURSE, COURSE_DIFF_ORG))

    def test_platform_course_admin_denied_on_library(self):
        """
        Namespace isolation: platform course glob must not grant lib access.
        """
        self.assertFalse(is_user_allowed(P_PLATFORM_COURSE_ADMIN, _VIEW_LIB, LIB_OWN))

    def test_platform_course_admin_denied_on_library_diff_org(self):
        self.assertFalse(is_user_allowed(P_PLATFORM_COURSE_ADMIN, _VIEW_LIB, LIB_DIFF_ORG))

    #  django_staff: bypass fires for lib + course
    def test_django_staff_allowed_on_library_via_bypass(self):
        self.assertTrue(is_user_allowed(P_STAFF, _VIEW_LIB, LIB_OWN))

    def test_django_staff_allowed_on_unassigned_library_via_bypass(self):
        self.assertTrue(is_user_allowed(P_STAFF, _VIEW_LIB, LIB_SAME_ORG))

    def test_django_staff_allowed_on_library_diff_org_via_bypass(self):
        self.assertTrue(is_user_allowed(P_STAFF, _VIEW_LIB, LIB_DIFF_ORG))

    def test_django_staff_allowed_on_course_via_bypass(self):
        self.assertTrue(is_user_allowed(P_STAFF, _VIEW_COURSE, COURSE_OWN))

    def test_django_staff_allowed_on_unassigned_course_via_bypass(self):
        self.assertTrue(is_user_allowed(P_STAFF, _VIEW_COURSE, COURSE_DIFF_ORG))


# Checks for get_visible_role_assignments_for_user

# The admin-view permission that gates visibility of each assignment type:
# ContentLibraryData.get_admin_view_permission() -> VIEW_LIBRARY_TEAM
# CourseOverviewData.get_admin_view_permission() -> COURSES_VIEW_COURSE_TEAM
# So:
#   - to see a lib assignment the viewer needs view_library_team on that scope.
#   - to see a course assignment the viewer needs view_course_team on that scope.
#
# library_admin role includes VIEW_LIBRARY_TEAM, so a lib_admin can see
# assignments in their own library/glob.
# course_admin role includes COURSES_VIEW_COURSE_TEAM, so a course_admin
# can see assignments in their own course/glob.


class TestDisclosureGate(RoleFixture):
    """
    Check get_visible_role_assignments_for_user visibility table.
    """

    def _scopes_visible_to(self, viewer_username):
        """Return the set of scope external_keys visible to viewer."""
        result = get_visible_role_assignments_for_user(
            allowed_for_user_external_key=viewer_username,
        )
        visible = set()
        for user_assignment in result:
            for assignment in user_assignment.assignments:
                visible.add(assignment.scope.external_key)
        return visible

    def test_nobody_sees_no_assignments(self):
        visible = self._scopes_visible_to(P_NOBODY)
        self.assertEqual(visible, set(), msg="nobody should see zero assignments")

    def test_lib_admin_sees_only_own_library(self):
        """
        lib_admin can see assignments in LIB_OWN (they hold view_library_team
        there) but not assignments in LIB_DIFF_ORG or COURSE_OWN.
        """
        visible = self._scopes_visible_to(P_LIB_ADMIN)
        self.assertIn(LIB_OWN, visible, msg="lib_admin must see assignments in their own library")
        self.assertNotIn(LIB_DIFF_ORG, visible, msg="lib_admin must not see other-org library")
        self.assertNotIn(COURSE_OWN, visible, msg="lib_admin must not see course assignments")

    def test_org_lib_admin_sees_all_orga_libs_but_not_orgb_or_courses(self):
        """
        org_lib_admin holds view_library_team on lib:OrgA:* so must see all
        OrgA library assignments but not OrgB or course assignments.
        """
        visible = self._scopes_visible_to(P_ORG_LIB_ADMIN)
        self.assertIn(LIB_OWN, visible, msg="org_lib_admin must see LIB_OWN (within OrgA)")
        self.assertNotIn(LIB_DIFF_ORG, visible, msg="org_lib_admin must not see OrgB library")
        self.assertNotIn(COURSE_OWN, visible, msg="org_lib_admin must not see course assignments")

    def test_platform_course_admin_sees_courses_but_not_libraries(self):
        """
        platform_course_admin holds view_course_team on course-v1:* so must
        see all course assignments but no library assignments.
        """
        visible = self._scopes_visible_to(P_PLATFORM_COURSE_ADMIN)
        self.assertIn(COURSE_OWN, visible, msg="platform_course_admin must see course assignments")
        self.assertNotIn(LIB_OWN, visible, msg="platform_course_admin must not see library assignments")
        self.assertNotIn(LIB_DIFF_ORG, visible, msg="platform_course_admin must not see any library assignment")

    def test_null_viewer_bypasses_filter_and_sees_all_assignments(self):
        """
        allowed_for_user_external_key=None is a documented bypass in
        _filter_allowed_assignments that skips every permission check and
        returns all assignments.

        This is intentional for the internal Python API — the caller (the
        REST layer) is responsible for always passing the current user's key.
        """
        # With a known viewer that has limited scope, we get a subset.
        limited = self._scopes_visible_to(P_LIB_ADMIN)

        # With viewer=None we get everything.
        all_result = get_visible_role_assignments_for_user(
            allowed_for_user_external_key=None,
        )
        all_scopes = set()
        for user_assignment in all_result:
            for assignment in user_assignment.assignments:
                all_scopes.add(assignment.scope.external_key)

        self.assertGreater(
            len(all_scopes),
            len(limited),
            msg=(
                "Null viewer must return more assignments than a restricted viewer. "
                "If this fails, the bypass may have been removed. If this is intentional, "
                "this test can be removed."
            ),
        )
        # Both the library and course seed assignments must be visible.
        self.assertIn(LIB_DIFF_ORG, all_scopes, msg="Null bypass must expose OrgB library assignment")
        self.assertIn(COURSE_OWN, all_scopes, msg="Null bypass must expose course assignment")


# Checks for get_scopes_for_subject_and_permission
class TestInverseQueryCrossNamespace(RoleFixture):
    """
    get_scopes_for_subject_and_permission respects namespace boundaries.
    A library persona must return no course scopes for a course permission,
    and vice versa.
    """

    def test_lib_admin_scopes_for_view_lib_contains_own_lib(self):
        scopes = get_scopes_for_subject_and_permission(
            UserData(external_key=P_LIB_ADMIN),
            permissions.VIEW_LIBRARY,
        )
        external_keys = [s.external_key for s in scopes]
        self.assertIn(LIB_OWN, external_keys)

    def test_lib_admin_scopes_for_view_course_is_empty(self):
        """
        Namespace isolation: lib persona must return no course scopes.
        """
        scopes = get_scopes_for_subject_and_permission(
            UserData(external_key=P_LIB_ADMIN),
            permissions.COURSES_VIEW_COURSE,
        )
        self.assertEqual(
            scopes,
            [],
            msg=(
                "lib_admin should have no course scopes for view_course. "
                "Non-empty result means namespace isolation is broken."
            ),
        )

    def test_course_admin_scopes_for_view_course_contains_own_course(self):
        scopes = get_scopes_for_subject_and_permission(
            UserData(external_key=P_COURSE_ADMIN),
            permissions.COURSES_VIEW_COURSE,
        )
        external_keys = [s.external_key for s in scopes]
        self.assertIn(COURSE_OWN, external_keys)

    def test_course_admin_scopes_for_view_lib_is_empty(self):
        """
        Namespace isolation: course persona must return no library scopes.
        """
        scopes = get_scopes_for_subject_and_permission(
            UserData(external_key=P_COURSE_ADMIN),
            permissions.VIEW_LIBRARY,
        )
        self.assertEqual(
            scopes,
            [],
            msg=(
                "course_admin should have no library scopes for view_library. "
                "Non-empty result means namespace isolation is broken."
            ),
        )

    def test_nobody_scopes_for_any_permission_is_empty(self):
        for perm in (permissions.VIEW_LIBRARY, permissions.COURSES_VIEW_COURSE):
            with self.subTest(permission=perm.action.external_key):
                scopes = get_scopes_for_subject_and_permission(
                    UserData(external_key=P_NOBODY),
                    perm,
                )
                self.assertEqual(scopes, [], msg=f"nobody must have no scopes for {perm}")

    def test_org_lib_admin_scopes_for_view_lib_covers_org_glob(self):
        """
        The org glob scope itself should appear in the result.
        """
        scopes = get_scopes_for_subject_and_permission(
            UserData(external_key=P_ORG_LIB_ADMIN),
            permissions.VIEW_LIBRARY,
        )
        external_keys = [s.external_key for s in scopes]
        self.assertIn(ORG_LIB_GLOB, external_keys)

    def test_org_lib_admin_scopes_for_view_course_is_empty(self):
        scopes = get_scopes_for_subject_and_permission(
            UserData(external_key=P_ORG_LIB_ADMIN),
            permissions.COURSES_VIEW_COURSE,
        )
        self.assertEqual(scopes, [], msg="org lib admin must have no course scopes")


class TestNoAccessControlReadPaths(RoleFixture):
    """
    The internal Python API exposes several read functions with no
    caller-level access control.  These are intentional — the REST
    layer is responsible for enforcing authorization.  Pinned here
    so that if access-control guards are ever added they are caught
    and reviewed.
    """

    def test_get_subject_role_assignments_has_no_caller_check(self):
        """
        get_subject_role_assignments(subject) is callable by anyone and
        returns the full assignment list for that subject. There is no
        caller/viewer parameter.
        """
        # Even P_NOBODY (no permissions) can read P_LIB_ADMIN's assignments.
        assignments = get_subject_role_assignments(UserData(external_key=P_LIB_ADMIN))
        self.assertGreaterEqual(
            len(assignments),
            1,
            msg="Expected at least one assignment for lib_admin",
        )
        scope_keys = [a.scope.external_key for a in assignments]
        self.assertIn(LIB_OWN, scope_keys)

    def test_get_superadmin_assignments_has_no_caller_check(self):
        """
        get_superadmin_assignments() lists Django staff/superusers with
        no caller-level permissions check. By design any internal caller can
        enumerate platform admins.
        """
        # P_NOBODY can call this, result should include P_STAFF
        result = get_superadmin_assignments()
        admin_usernames = [a.user.username for a in result]
        self.assertIn(
            P_STAFF,
            admin_usernames,
            msg=(
                f"Expected {P_STAFF!r} (is_staff=True) in get_superadmin_assignments(). "
                "If not found, we may have changed assumptions about returning staff/superusers."
            ),
        )
        self.assertNotIn(
            P_NOBODY,
            admin_usernames,
            msg="nobody (no is_staff) must not appear in superadmin list",
        )
