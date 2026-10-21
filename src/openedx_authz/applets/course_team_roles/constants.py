"""Legacy compatibility permissions for course-team roles."""

from openedx_authz.data import ActionData, PermissionData

__all__ = [
    "COURSES_LEGACY_BETA_TESTER_PERMISSIONS",
    "COURSES_LEGACY_DATA_RESEARCHER_PERMISSIONS",
    "COURSES_LEGACY_INSTRUCTOR_ROLE_PERMISSIONS",
    "COURSES_LEGACY_LIMITED_STAFF_ROLE_PERMISSIONS",
    "COURSES_LEGACY_STAFF_ROLE_PERMISSIONS",
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
