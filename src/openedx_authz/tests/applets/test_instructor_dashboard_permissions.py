"""Enforcement tests for the Instructor Dashboard permissions contributed by built-in applets."""

from itertools import product

from ddt import data, ddt, unpack

from openedx_authz.api.users import assign_role_to_user_in_scope, is_user_allowed
from openedx_authz.constants import permissions, roles
from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.engine.renderer import PolicyRenderer
from openedx_authz.engine.schema.pipeline import SchemaPipeline
from openedx_authz.tests.api.test_roles import BaseRolesTestCase

COURSE_KEY = "course-v1:TestOrg+Dashboard+2026_T1"
OTHER_COURSE_KEY = "course-v1:TestOrg+Dashboard+2026_T2"

INSTRUCTOR_DASHBOARD_PERMISSIONS = (
    permissions.COURSES_VIEW_COURSE_INFO,
    permissions.COURSES_VIEW_ENROLLMENTS,
    permissions.COURSES_ENROLL_LEARNERS,
    permissions.COURSES_UNENROLL_LEARNERS,
    permissions.COURSES_VIEW_GRADEBOOK,
    permissions.COURSES_MANAGE_LEARNER_GRADING,
    permissions.COURSES_VIEW_LEARNER_EXTENSIONS,
    permissions.COURSES_MANAGE_LEARNER_EXTENSIONS,
    permissions.COURSES_VIEW_COHORTS,
    permissions.COURSES_MANAGE_COHORTS,
)

USERS_WITH_EXPECTED_ACCESS = (
    ("dashboard_admin", True),
    ("dashboard_staff", True),
    ("dashboard_learner", False),
)


@ddt
class TestInstructorDashboardPermissions(BaseRolesTestCase):
    """Course-team roles receive the Instructor Dashboard permissions through applet role extensions."""

    @classmethod
    def _seed_database_with_policies(cls):
        """Seed the database with the policies rendered from the compiled built-in schema."""
        enforcer = AuthzEnforcer.get_enforcer()
        enforcer.load_policy()
        for row in PolicyRenderer().render(SchemaPipeline().compile()).rows:
            enforcer.add_policy(*row.as_policy())
        enforcer.clear_policy()

    @classmethod
    def setUpClass(cls):
        """Assign the course-team roles used by every test in the class."""
        super().setUpClass()
        assign_role_to_user_in_scope("dashboard_admin", roles.COURSE_ADMIN.external_key, COURSE_KEY)
        assign_role_to_user_in_scope("dashboard_staff", roles.COURSE_STAFF.external_key, COURSE_KEY)

    @data(*((username, permission, expected) for (username, expected), permission in product(
        USERS_WITH_EXPECTED_ACCESS, INSTRUCTOR_DASHBOARD_PERMISSIONS
    )))
    @unpack
    def test_course_team_roles_are_allowed_new_permissions(self, username, permission, expected_result):
        """Course Admin and Course Staff are allowed every new permission, and a user without a role is denied."""
        result = is_user_allowed(
            user_external_key=username,
            action_external_key=permission.identifier,
            scope_external_key=COURSE_KEY,
        )

        self.assertEqual(result, expected_result)

    @data(*product(("dashboard_admin", "dashboard_staff"), INSTRUCTOR_DASHBOARD_PERMISSIONS))
    @unpack
    def test_new_permissions_are_limited_to_the_assigned_course(self, username, permission):
        """A course-team role assigned in one course does not allow the new permissions in another course."""
        result = is_user_allowed(
            user_external_key=username,
            action_external_key=permission.identifier,
            scope_external_key=OTHER_COURSE_KEY,
        )

        self.assertFalse(result)

    @data(
        ("dashboard_admin", permissions.COURSES_VIEW_COURSE_TEAM, True),
        ("dashboard_staff", permissions.COURSES_VIEW_COURSE_TEAM, True),
        ("dashboard_admin", permissions.COURSES_MANAGE_COURSE_TEAM, True),
        ("dashboard_staff", permissions.COURSES_MANAGE_COURSE_TEAM, False),
        ("dashboard_admin", permissions.COURSES_VIEW_GRADING_SETTINGS, True),
        ("dashboard_staff", permissions.COURSES_VIEW_GRADING_SETTINGS, True),
    )
    @unpack
    def test_reused_permissions_keep_their_current_assignments(self, username, permission, expected_result):
        """The Course Authoring permissions reused by the Instructor Dashboard keep their existing role assignments."""
        result = is_user_allowed(
            user_external_key=username,
            action_external_key=permission.identifier,
            scope_external_key=COURSE_KEY,
        )

        self.assertEqual(result, expected_result)
