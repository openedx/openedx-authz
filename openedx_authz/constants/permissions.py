"""
Default permission constants.
"""

from openedx_authz.api.data import ActionData, PermissionData

# Content Library Permissions

CONTENT_LIBRARIES_NAMESPACE = "content_libraries"

VIEW_LIBRARY = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.view_library"),
    effect="allow",
)
MANAGE_LIBRARY_TAGS = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.manage_library_tags"),
    effect="allow",
)
DELETE_LIBRARY = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.delete_library"),
    effect="allow",
)
EDIT_LIBRARY_CONTENT = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.edit_library_content"),
    effect="allow",
)
PUBLISH_LIBRARY_CONTENT = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.publish_library_content"),
    effect="allow",
)
REUSE_LIBRARY_CONTENT = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.reuse_library_content"),
    effect="allow",
)
VIEW_LIBRARY_TEAM = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.view_library_team"),
    effect="allow",
)
MANAGE_LIBRARY_TEAM = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.manage_library_team"),
    effect="allow",
)

CREATE_LIBRARY_COLLECTION = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.create_library_collection"),
    effect="allow",
)
EDIT_LIBRARY_COLLECTION = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.edit_library_collection"),
    effect="allow",
)
DELETE_LIBRARY_COLLECTION = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.delete_library_collection"),
    effect="allow",
)

# Course Permissions

COURSES_NAMESPACE = "courses"

COURSES_VIEW_COURSE = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.view_course"),
    effect="allow",
)

COURSES_CREATE_COURSE = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.create_course"),
    effect="allow",
)

COURSES_EDIT_COURSE_CONTENT = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.edit_course_content"),
    effect="allow",
)

COURSES_PUBLISH_COURSE_CONTENT = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.publish_course_content"),
    effect="allow",
)

COURSES_MANAGE_LIBRARY_UPDATES = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.manage_library_updates"),
    effect="allow",
)

COURSES_VIEW_COURSE_UPDATES = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.view_course_updates"),
    effect="allow",
)

COURSES_MANAGE_COURSE_UPDATES = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.manage_course_updates"),
    effect="allow",
)

COURSES_VIEW_PAGES_AND_RESOURCES = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.view_pages_and_resources"),
    effect="allow",
)

COURSES_MANAGE_PAGES_AND_RESOURCES = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.manage_pages_and_resources"),
    effect="allow",
)

COURSES_VIEW_FILES = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.view_files"),
    effect="allow",
)

COURSES_CREATE_FILES = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.create_files"),
    effect="allow",
)

COURSES_DELETE_FILES = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.delete_files"),
    effect="allow",
)

COURSES_EDIT_FILES = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.edit_files"),
    effect="allow",
)

COURSES_VIEW_SCHEDULE_AND_DETAILS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.view_schedule_and_details"),
    effect="allow",
)

COURSES_EDIT_SCHEDULE = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.edit_schedule"),
    effect="allow",
)

COURSES_EDIT_DETAILS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.edit_details"),
    effect="allow",
)

COURSES_VIEW_GRADING_SETTINGS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.view_grading_settings"),
    effect="allow",
)

COURSES_EDIT_GRADING_SETTINGS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.edit_grading_settings"),
    effect="allow",
)

COURSES_VIEW_COURSE_TEAM = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.view_course_team"),
    effect="allow",
)

COURSES_MANAGE_COURSE_TEAM = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.manage_course_team"),
    effect="allow",
)

COURSES_MANAGE_GROUP_CONFIGURATIONS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.manage_group_configurations"),
    effect="allow",
)

COURSES_MANAGE_ADVANCED_SETTINGS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.manage_advanced_settings"),
    effect="allow",
)

COURSES_MANAGE_CERTIFICATES = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.manage_certificates"),
    effect="allow",
)

COURSES_IMPORT_COURSE = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.import_course"),
    effect="allow",
)

COURSES_EXPORT_COURSE = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.export_course"),
    effect="allow",
)

COURSES_EXPORT_TAGS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.export_tags"),
    effect="allow",
)

COURSES_VIEW_CHECKLISTS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.view_checklists"),
    effect="allow",
)

COURSES_MANAGE_TAGS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.manage_tags"),
    effect="allow",
)

COURSES_MANAGE_TAXONOMIES = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.manage_taxonomies"),
    effect="allow",
)

# Legacy Course permissions
# These permissions allow backwards compatibility with legacy code that depends on the old roles system
# These relate to legacy roles, if a openedx-authz role has one of these permissions,
# it will have the same permissions as the equivalent legacy roles on code that has not been updated to the new system.

COURSES_LEGACY_INSTRUCTOR_ROLE_PERMISSIONS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.legacy_instructor_role_permissions"),
    effect="allow",
)

COURSES_LEGACY_STAFF_ROLE_PERMISSIONS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.legacy_staff_role_permissions"),
    effect="allow",
)

COURSES_LEGACY_LIMITED_STAFF_ROLE_PERMISSIONS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.legacy_limited_staff_role_permissions"),
    effect="allow",
)

COURSES_LEGACY_DATA_RESEARCHER_PERMISSIONS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.legacy_data_researcher_permissions"),
    effect="allow",
)

COURSES_LEGACY_BETA_TESTER_PERMISSIONS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.legacy_beta_tester_permissions"),
    effect="allow",
)
