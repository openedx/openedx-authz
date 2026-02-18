"""
Default roles and their associated permissions.
"""

from openedx_authz.api.data import RoleData
from openedx_authz.constants import permissions

# Library Roles and Permissions

# Define the associated permissions for each role

LIBRARY_ADMIN_PERMISSIONS = [
    permissions.VIEW_LIBRARY,
    permissions.MANAGE_LIBRARY_TAGS,
    permissions.DELETE_LIBRARY,
    permissions.EDIT_LIBRARY_CONTENT,
    permissions.PUBLISH_LIBRARY_CONTENT,
    permissions.REUSE_LIBRARY_CONTENT,
    permissions.VIEW_LIBRARY_TEAM,
    permissions.MANAGE_LIBRARY_TEAM,
    permissions.CREATE_LIBRARY_COLLECTION,
    permissions.EDIT_LIBRARY_COLLECTION,
    permissions.DELETE_LIBRARY_COLLECTION,
]

LIBRARY_AUTHOR_PERMISSIONS = [
    permissions.VIEW_LIBRARY,
    permissions.MANAGE_LIBRARY_TAGS,
    permissions.EDIT_LIBRARY_CONTENT,
    permissions.PUBLISH_LIBRARY_CONTENT,
    permissions.REUSE_LIBRARY_CONTENT,
    permissions.VIEW_LIBRARY_TEAM,
    permissions.CREATE_LIBRARY_COLLECTION,
    permissions.EDIT_LIBRARY_COLLECTION,
    permissions.DELETE_LIBRARY_COLLECTION,
]

LIBRARY_CONTRIBUTOR_PERMISSIONS = [
    permissions.VIEW_LIBRARY,
    permissions.MANAGE_LIBRARY_TAGS,
    permissions.EDIT_LIBRARY_CONTENT,
    permissions.REUSE_LIBRARY_CONTENT,
    permissions.VIEW_LIBRARY_TEAM,
    permissions.CREATE_LIBRARY_COLLECTION,
    permissions.EDIT_LIBRARY_COLLECTION,
    permissions.DELETE_LIBRARY_COLLECTION,
]

LIBRARY_USER_PERMISSIONS = [
    permissions.VIEW_LIBRARY,
    permissions.REUSE_LIBRARY_CONTENT,
    permissions.VIEW_LIBRARY_TEAM,
]

LIBRARY_ADMIN = RoleData(external_key="library_admin", permissions=LIBRARY_ADMIN_PERMISSIONS)
LIBRARY_AUTHOR = RoleData(external_key="library_author", permissions=LIBRARY_AUTHOR_PERMISSIONS)
LIBRARY_CONTRIBUTOR = RoleData(external_key="library_contributor", permissions=LIBRARY_CONTRIBUTOR_PERMISSIONS)
LIBRARY_USER = RoleData(external_key="library_user", permissions=LIBRARY_USER_PERMISSIONS)


# Course Roles and Permissions

COURSE_AUDITOR_PERMISSIONS = [
    permissions.COURSES_VIEW_COURSE,
    permissions.COURSES_VIEW_COURSE_UPDATES,
    permissions.COURSES_VIEW_PAGES_AND_RESOURCES,
    permissions.COURSES_VIEW_FILES,
    permissions.COURSES_VIEW_GRADING_SETTINGS,
    permissions.COURSES_VIEW_CHECKLISTS,
    permissions.COURSES_VIEW_COURSE_TEAM,
    permissions.COURSES_VIEW_SCHEDULE_AND_DETAILS,
]

COURSE_AUDITOR = RoleData(external_key="course_auditor", permissions=COURSE_AUDITOR_PERMISSIONS)

COURSE_EDITOR_PERMISSIONS = [
    permissions.COURSES_VIEW_COURSE,
    permissions.COURSES_VIEW_COURSE_UPDATES,
    permissions.COURSES_VIEW_PAGES_AND_RESOURCES,
    permissions.COURSES_VIEW_FILES,
    permissions.COURSES_VIEW_GRADING_SETTINGS,
    permissions.COURSES_VIEW_CHECKLISTS,
    permissions.COURSES_VIEW_COURSE_TEAM,
    permissions.COURSES_VIEW_SCHEDULE_AND_DETAILS,
    permissions.COURSES_EDIT_COURSE_CONTENT,
    permissions.COURSES_MANAGE_LIBRARY_UPDATES,
    permissions.COURSES_MANAGE_COURSE_UPDATES,
    permissions.COURSES_MANAGE_PAGES_AND_RESOURCES,
    permissions.COURSES_CREATE_FILES,
    permissions.COURSES_EDIT_FILES,
    permissions.COURSES_EDIT_GRADING_SETTINGS,
    permissions.COURSES_MANAGE_GROUP_CONFIGURATIONS,
    permissions.COURSES_EDIT_DETAILS,
    permissions.COURSES_MANAGE_TAGS,
]

COURSE_EDITOR = RoleData(external_key="course_editor", permissions=COURSE_EDITOR_PERMISSIONS)

COURSE_ADMIN_PERMISSIONS = [
    permissions.COURSES_LEGACY_INSTRUCTOR_ROLE_PERMISSIONS,
    permissions.COURSES_VIEW_COURSE,
    permissions.COURSES_VIEW_COURSE_UPDATES,
    permissions.COURSES_VIEW_PAGES_AND_RESOURCES,
    permissions.COURSES_VIEW_FILES,
    permissions.COURSES_VIEW_GRADING_SETTINGS,
    permissions.COURSES_VIEW_CHECKLISTS,
    permissions.COURSES_VIEW_COURSE_TEAM,
    permissions.COURSES_VIEW_SCHEDULE_AND_DETAILS,
    permissions.COURSES_EDIT_COURSE_CONTENT,
    permissions.COURSES_MANAGE_LIBRARY_UPDATES,
    permissions.COURSES_MANAGE_COURSE_UPDATES,
    permissions.COURSES_MANAGE_PAGES_AND_RESOURCES,
    permissions.COURSES_CREATE_FILES,
    permissions.COURSES_EDIT_FILES,
    permissions.COURSES_EDIT_GRADING_SETTINGS,
    permissions.COURSES_MANAGE_GROUP_CONFIGURATIONS,
    permissions.COURSES_EDIT_DETAILS,
    permissions.COURSES_MANAGE_TAGS,
    permissions.COURSES_PUBLISH_COURSE_CONTENT,
    permissions.COURSES_DELETE_FILES,
    permissions.COURSES_EDIT_SCHEDULE,
    permissions.COURSES_MANAGE_ADVANCED_SETTINGS,
    permissions.COURSES_MANAGE_CERTIFICATES,
    permissions.COURSES_IMPORT_COURSE,
    permissions.COURSES_EXPORT_COURSE,
    permissions.COURSES_EXPORT_TAGS,
    permissions.COURSES_MANAGE_COURSE_TEAM,
    permissions.COURSES_MANAGE_TAXONOMIES,
]

COURSE_ADMIN = RoleData(external_key="course_admin", permissions=COURSE_ADMIN_PERMISSIONS)

COURSE_STAFF_PERMISSIONS = [
    permissions.COURSES_LEGACY_STAFF_ROLE_PERMISSIONS,
    permissions.COURSES_VIEW_COURSE,
    permissions.COURSES_VIEW_COURSE_UPDATES,
    permissions.COURSES_VIEW_PAGES_AND_RESOURCES,
    permissions.COURSES_VIEW_FILES,
    permissions.COURSES_VIEW_GRADING_SETTINGS,
    permissions.COURSES_VIEW_CHECKLISTS,
    permissions.COURSES_VIEW_COURSE_TEAM,
    permissions.COURSES_VIEW_SCHEDULE_AND_DETAILS,
    permissions.COURSES_EDIT_COURSE_CONTENT,
    permissions.COURSES_MANAGE_LIBRARY_UPDATES,
    permissions.COURSES_MANAGE_COURSE_UPDATES,
    permissions.COURSES_MANAGE_PAGES_AND_RESOURCES,
    permissions.COURSES_CREATE_FILES,
    permissions.COURSES_EDIT_FILES,
    permissions.COURSES_EDIT_GRADING_SETTINGS,
    permissions.COURSES_MANAGE_GROUP_CONFIGURATIONS,
    permissions.COURSES_EDIT_DETAILS,
    permissions.COURSES_MANAGE_TAGS,
    permissions.COURSES_PUBLISH_COURSE_CONTENT,
    permissions.COURSES_DELETE_FILES,
    permissions.COURSES_EDIT_SCHEDULE,
    permissions.COURSES_MANAGE_ADVANCED_SETTINGS,
    permissions.COURSES_MANAGE_CERTIFICATES,
    permissions.COURSES_IMPORT_COURSE,
    permissions.COURSES_EXPORT_COURSE,
    permissions.COURSES_EXPORT_TAGS,
]

COURSE_LIMITED_STAFF_PERMISSIONS = []

COURSE_DATA_RESEARCHER_PERMISSIONS = []

COURSE_ADMIN = RoleData(external_key="course_admin", permissions=COURSE_ADMIN_PERMISSIONS)
COURSE_STAFF = RoleData(external_key="course_staff", permissions=COURSE_STAFF_PERMISSIONS)

COURSE_LIMITED_STAFF_PERMISSIONS = [
    permissions.COURSES_LEGACY_LIMITED_STAFF_ROLE_PERMISSIONS,
]

COURSE_LIMITED_STAFF = RoleData(external_key="course_limited_staff", permissions=COURSE_LIMITED_STAFF_PERMISSIONS)

COURSE_DATA_RESEARCHER_PERMISSIONS = [
    permissions.COURSES_LEGACY_DATA_RESEARCHER_PERMISSIONS,
]

COURSE_DATA_RESEARCHER = RoleData(external_key="course_data_researcher", permissions=COURSE_DATA_RESEARCHER_PERMISSIONS)

COURSE_BETA_TESTER_PERMISSIONS = [
    permissions.COURSES_LEGACY_BETA_TESTER_PERMISSIONS,
]

COURSE_BETA_TESTER = RoleData(external_key="course_beta_tester", permissions=COURSE_BETA_TESTER_PERMISSIONS)

# Map of legacy course role names to their equivalent new roles
# This mapping must be unique in both directions, since it may be used as a reverse lookup (value → key).
# If multiple keys share the same value, it will lead to collisions.
LEGACY_COURSE_ROLE_EQUIVALENCES = {
    "instructor": COURSE_ADMIN.external_key,
    "staff": COURSE_STAFF.external_key,
    "limited_staff": COURSE_LIMITED_STAFF.external_key,
    "data_researcher": COURSE_DATA_RESEARCHER.external_key,
    "beta_testers": COURSE_BETA_TESTER.external_key,
}
