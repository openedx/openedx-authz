"""
Default roles and their associated permissions.
"""

from openedx_authz.api.data import RoleData
from openedx_authz.applets.course_authoring import constants as course_authoring
from openedx_authz.applets.course_team_roles.constants import (
    COURSE_ADMIN_ID,
    COURSE_AUDITOR_ID,
    COURSE_BETA_TESTER_ID,
    COURSE_DATA_RESEARCHER_ID,
    COURSE_EDITOR_ID,
    COURSE_LIMITED_STAFF_ID,
    COURSE_STAFF_ID,
    COURSES_LEGACY_BETA_TESTER_PERMISSIONS,
    COURSES_LEGACY_DATA_RESEARCHER_PERMISSIONS,
    COURSES_LEGACY_INSTRUCTOR_ROLE_PERMISSIONS,
    COURSES_LEGACY_LIMITED_STAFF_ROLE_PERMISSIONS,
    COURSES_LEGACY_STAFF_ROLE_PERMISSIONS,
)

# Course Roles and Permissions

COURSE_AUDITOR_PERMISSIONS = [
    course_authoring.COURSES_VIEW_COURSE,
    course_authoring.COURSES_VIEW_COURSE_UPDATES,
    course_authoring.COURSES_VIEW_PAGES_AND_RESOURCES,
    course_authoring.COURSES_VIEW_FILES,
    course_authoring.COURSES_VIEW_GRADING_SETTINGS,
    course_authoring.COURSES_VIEW_CHECKLISTS,
    course_authoring.COURSES_VIEW_COURSE_TEAM,
    course_authoring.COURSES_VIEW_SCHEDULE_AND_DETAILS,
    course_authoring.COURSES_VIEW_ADVANCED_SETTINGS,
    course_authoring.COURSES_VIEW_CERTIFICATES,
    course_authoring.COURSES_VIEW_GROUP_CONFIGURATIONS,
    course_authoring.COURSES_VIEW_LIBRARY_UPDATES,
]

COURSE_AUDITOR = RoleData(
    external_key=COURSE_AUDITOR_ID,
    permissions=COURSE_AUDITOR_PERMISSIONS,
)

COURSE_EDITOR_PERMISSIONS = [
    course_authoring.COURSES_VIEW_COURSE,
    course_authoring.COURSES_VIEW_COURSE_UPDATES,
    course_authoring.COURSES_VIEW_PAGES_AND_RESOURCES,
    course_authoring.COURSES_VIEW_FILES,
    course_authoring.COURSES_VIEW_GRADING_SETTINGS,
    course_authoring.COURSES_VIEW_CHECKLISTS,
    course_authoring.COURSES_VIEW_COURSE_TEAM,
    course_authoring.COURSES_VIEW_SCHEDULE_AND_DETAILS,
    course_authoring.COURSES_VIEW_ADVANCED_SETTINGS,
    course_authoring.COURSES_VIEW_CERTIFICATES,
    course_authoring.COURSES_VIEW_GROUP_CONFIGURATIONS,
    course_authoring.COURSES_VIEW_LIBRARY_UPDATES,
    course_authoring.COURSES_EDIT_COURSE_CONTENT,
    course_authoring.COURSES_MANAGE_LIBRARY_UPDATES,
    course_authoring.COURSES_MANAGE_COURSE_UPDATES,
    course_authoring.COURSES_MANAGE_PAGES_AND_RESOURCES,
    course_authoring.COURSES_CREATE_FILES,
    course_authoring.COURSES_EDIT_FILES,
    course_authoring.COURSES_EDIT_GRADING_SETTINGS,
    course_authoring.COURSES_MANAGE_GROUP_CONFIGURATIONS,
    course_authoring.COURSES_EDIT_DETAILS,
    course_authoring.COURSES_MANAGE_TAGS,
]

COURSE_EDITOR = RoleData(external_key=COURSE_EDITOR_ID, permissions=COURSE_EDITOR_PERMISSIONS)

COURSE_ADMIN_PERMISSIONS = [
    COURSES_LEGACY_INSTRUCTOR_ROLE_PERMISSIONS,
    course_authoring.COURSES_VIEW_COURSE,
    course_authoring.COURSES_VIEW_COURSE_UPDATES,
    course_authoring.COURSES_VIEW_PAGES_AND_RESOURCES,
    course_authoring.COURSES_VIEW_FILES,
    course_authoring.COURSES_VIEW_GRADING_SETTINGS,
    course_authoring.COURSES_VIEW_CHECKLISTS,
    course_authoring.COURSES_VIEW_COURSE_TEAM,
    course_authoring.COURSES_VIEW_SCHEDULE_AND_DETAILS,
    course_authoring.COURSES_VIEW_ADVANCED_SETTINGS,
    course_authoring.COURSES_VIEW_CERTIFICATES,
    course_authoring.COURSES_VIEW_GROUP_CONFIGURATIONS,
    course_authoring.COURSES_VIEW_LIBRARY_UPDATES,
    course_authoring.COURSES_EDIT_COURSE_CONTENT,
    course_authoring.COURSES_MANAGE_LIBRARY_UPDATES,
    course_authoring.COURSES_MANAGE_COURSE_UPDATES,
    course_authoring.COURSES_MANAGE_PAGES_AND_RESOURCES,
    course_authoring.COURSES_CREATE_FILES,
    course_authoring.COURSES_EDIT_FILES,
    course_authoring.COURSES_EDIT_GRADING_SETTINGS,
    course_authoring.COURSES_MANAGE_GROUP_CONFIGURATIONS,
    course_authoring.COURSES_EDIT_DETAILS,
    course_authoring.COURSES_MANAGE_TAGS,
    course_authoring.COURSES_PUBLISH_COURSE_CONTENT,
    course_authoring.COURSES_DELETE_FILES,
    course_authoring.COURSES_EDIT_SCHEDULE,
    course_authoring.COURSES_MANAGE_ADVANCED_SETTINGS,
    course_authoring.COURSES_MANAGE_CERTIFICATES,
    course_authoring.COURSES_IMPORT_COURSE,
    course_authoring.COURSES_EXPORT_COURSE,
    course_authoring.COURSES_EXPORT_TAGS,
    course_authoring.COURSES_MANAGE_COURSE_TEAM,
    course_authoring.COURSES_MANAGE_TAXONOMIES,
]

COURSE_ADMIN = RoleData(external_key=COURSE_ADMIN_ID, permissions=COURSE_ADMIN_PERMISSIONS)

COURSE_STAFF_PERMISSIONS = [
    COURSES_LEGACY_STAFF_ROLE_PERMISSIONS,
    course_authoring.COURSES_VIEW_COURSE,
    course_authoring.COURSES_VIEW_COURSE_UPDATES,
    course_authoring.COURSES_VIEW_PAGES_AND_RESOURCES,
    course_authoring.COURSES_VIEW_FILES,
    course_authoring.COURSES_VIEW_GRADING_SETTINGS,
    course_authoring.COURSES_VIEW_CHECKLISTS,
    course_authoring.COURSES_VIEW_COURSE_TEAM,
    course_authoring.COURSES_VIEW_SCHEDULE_AND_DETAILS,
    course_authoring.COURSES_VIEW_ADVANCED_SETTINGS,
    course_authoring.COURSES_VIEW_CERTIFICATES,
    course_authoring.COURSES_VIEW_GROUP_CONFIGURATIONS,
    course_authoring.COURSES_VIEW_LIBRARY_UPDATES,
    course_authoring.COURSES_EDIT_COURSE_CONTENT,
    course_authoring.COURSES_MANAGE_LIBRARY_UPDATES,
    course_authoring.COURSES_MANAGE_COURSE_UPDATES,
    course_authoring.COURSES_MANAGE_PAGES_AND_RESOURCES,
    course_authoring.COURSES_CREATE_FILES,
    course_authoring.COURSES_EDIT_FILES,
    course_authoring.COURSES_EDIT_GRADING_SETTINGS,
    course_authoring.COURSES_MANAGE_GROUP_CONFIGURATIONS,
    course_authoring.COURSES_EDIT_DETAILS,
    course_authoring.COURSES_MANAGE_TAGS,
    course_authoring.COURSES_PUBLISH_COURSE_CONTENT,
    course_authoring.COURSES_DELETE_FILES,
    course_authoring.COURSES_EDIT_SCHEDULE,
    course_authoring.COURSES_MANAGE_ADVANCED_SETTINGS,
    course_authoring.COURSES_MANAGE_CERTIFICATES,
    course_authoring.COURSES_IMPORT_COURSE,
    course_authoring.COURSES_EXPORT_COURSE,
    course_authoring.COURSES_EXPORT_TAGS,
]

COURSE_STAFF = RoleData(external_key=COURSE_STAFF_ID, permissions=COURSE_STAFF_PERMISSIONS)

COURSE_LIMITED_STAFF_PERMISSIONS = [
    COURSES_LEGACY_LIMITED_STAFF_ROLE_PERMISSIONS,
]

COURSE_LIMITED_STAFF = RoleData(
    external_key=COURSE_LIMITED_STAFF_ID,
    permissions=COURSE_LIMITED_STAFF_PERMISSIONS,
)

COURSE_DATA_RESEARCHER_PERMISSIONS = [
    COURSES_LEGACY_DATA_RESEARCHER_PERMISSIONS,
]

COURSE_DATA_RESEARCHER = RoleData(
    external_key=COURSE_DATA_RESEARCHER_ID,
    permissions=COURSE_DATA_RESEARCHER_PERMISSIONS,
)

COURSE_BETA_TESTER_PERMISSIONS = [
    COURSES_LEGACY_BETA_TESTER_PERMISSIONS,
]

COURSE_BETA_TESTER = RoleData(
    external_key=COURSE_BETA_TESTER_ID,
    permissions=COURSE_BETA_TESTER_PERMISSIONS,
)

# This is a known LMS-only permission, but doesn't actually grant anything yet.
#
# It is intended to be handled in the Willow time frame.
CCX_COACH_PERMISSIONS = []
CCX_COACH = RoleData(external_key="ccx_coach", permissions=CCX_COACH_PERMISSIONS)


# Map of legacy course role names to their equivalent new roles
# This mapping must be unique in both directions, since it may be used as a reverse lookup (value → key).
# If multiple keys share the same value, it will lead to collisions.
LEGACY_COURSE_ROLE_EQUIVALENCES = {
    "instructor": COURSE_ADMIN.external_key,
    "staff": COURSE_STAFF.external_key,
    "limited_staff": COURSE_LIMITED_STAFF.external_key,
    "data_researcher": COURSE_DATA_RESEARCHER.external_key,
    "beta_testers": COURSE_BETA_TESTER.external_key,
    "ccx_coach": CCX_COACH.external_key,
}

__all__ = [
    "CCX_COACH",
    "CCX_COACH_PERMISSIONS",
    "COURSE_ADMIN",
    "COURSE_ADMIN_PERMISSIONS",
    "COURSE_AUDITOR",
    "COURSE_AUDITOR_PERMISSIONS",
    "COURSE_BETA_TESTER",
    "COURSE_BETA_TESTER_PERMISSIONS",
    "COURSE_DATA_RESEARCHER",
    "COURSE_DATA_RESEARCHER_PERMISSIONS",
    "COURSE_EDITOR",
    "COURSE_EDITOR_PERMISSIONS",
    "COURSE_LIMITED_STAFF",
    "COURSE_LIMITED_STAFF_PERMISSIONS",
    "COURSE_STAFF",
    "COURSE_STAFF_PERMISSIONS",
    "LEGACY_COURSE_ROLE_EQUIVALENCES",
]
