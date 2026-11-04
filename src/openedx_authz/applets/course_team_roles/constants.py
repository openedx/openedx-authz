"""Course-team role and legacy compatibility permission constants."""

from openedx_authz.data import ActionData, PermissionData, RoleData

__all__ = [
    "COURSES_LEGACY_BETA_TESTER_PERMISSIONS",
    "COURSES_LEGACY_DATA_RESEARCHER_PERMISSIONS",
    "COURSES_LEGACY_INSTRUCTOR_ROLE_PERMISSIONS",
    "COURSES_LEGACY_LIMITED_STAFF_ROLE_PERMISSIONS",
    "COURSES_LEGACY_STAFF_ROLE_PERMISSIONS",
    "CCX_COACH",
    "COURSE_ADMIN",
    "COURSE_AUDITOR",
    "COURSE_BETA_TESTER",
    "COURSE_DATA_RESEARCHER",
    "COURSE_EDITOR",
    "COURSE_LIMITED_STAFF",
    "COURSE_STAFF",
    "LEGACY_COURSE_ROLE_EQUIVALENCES",
]

COURSES_NAMESPACE = "courses"

COURSES_LEGACY_INSTRUCTOR_ROLE_PERMISSIONS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.legacy_instructor_role_permissions"), effect="allow"
)
COURSES_LEGACY_STAFF_ROLE_PERMISSIONS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.legacy_staff_role_permissions"), effect="allow"
)
COURSES_LEGACY_LIMITED_STAFF_ROLE_PERMISSIONS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.legacy_limited_staff_role_permissions"), effect="allow"
)
COURSES_LEGACY_DATA_RESEARCHER_PERMISSIONS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.legacy_data_researcher_permissions"), effect="allow"
)
COURSES_LEGACY_BETA_TESTER_PERMISSIONS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.legacy_beta_tester_permissions"), effect="allow"
)

COURSE_AUDITOR = RoleData(external_key="course_auditor")
COURSE_EDITOR = RoleData(external_key="course_editor")
COURSE_ADMIN = RoleData(external_key="course_admin")
COURSE_STAFF = RoleData(external_key="course_staff")
COURSE_LIMITED_STAFF = RoleData(external_key="course_limited_staff")
COURSE_DATA_RESEARCHER = RoleData(external_key="course_data_researcher")
COURSE_BETA_TESTER = RoleData(external_key="course_beta_tester")

# This is a known LMS-only permission, but does not grant anything yet.
CCX_COACH = RoleData(external_key="ccx_coach")

# This mapping must be unique in both directions because it may be reversed.
LEGACY_COURSE_ROLE_EQUIVALENCES = {
    "instructor": COURSE_ADMIN.external_key,
    "staff": COURSE_STAFF.external_key,
    "limited_staff": COURSE_LIMITED_STAFF.external_key,
    "data_researcher": COURSE_DATA_RESEARCHER.external_key,
    "beta_testers": COURSE_BETA_TESTER.external_key,
    "ccx_coach": CCX_COACH.external_key,
}
