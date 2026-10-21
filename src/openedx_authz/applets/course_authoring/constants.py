"""Course Authoring permission constants and course-role contributions."""

from openedx_authz.data import ActionData, PermissionData

__all__ = [
    "COURSES_NAMESPACE",
    "COURSES_VIEW_COURSE",
    "COURSES_VIEW_COURSE_TEAM",
    "COURSES_MANAGE_COURSE_TEAM",
    "COURSES_CREATE_COURSE",
    "COURSES_EDIT_COURSE_CONTENT",
    "COURSES_PUBLISH_COURSE_CONTENT",
    "COURSES_VIEW_LIBRARY_UPDATES",
    "COURSES_MANAGE_LIBRARY_UPDATES",
    "COURSES_VIEW_COURSE_UPDATES",
    "COURSES_MANAGE_COURSE_UPDATES",
    "COURSES_VIEW_PAGES_AND_RESOURCES",
    "COURSES_MANAGE_PAGES_AND_RESOURCES",
    "COURSES_VIEW_FILES",
    "COURSES_CREATE_FILES",
    "COURSES_DELETE_FILES",
    "COURSES_EDIT_FILES",
    "COURSES_VIEW_SCHEDULE_AND_DETAILS",
    "COURSES_EDIT_SCHEDULE",
    "COURSES_EDIT_DETAILS",
    "COURSES_VIEW_GRADING_SETTINGS",
    "COURSES_EDIT_GRADING_SETTINGS",
    "COURSES_VIEW_GROUP_CONFIGURATIONS",
    "COURSES_MANAGE_GROUP_CONFIGURATIONS",
    "COURSES_VIEW_ADVANCED_SETTINGS",
    "COURSES_MANAGE_ADVANCED_SETTINGS",
    "COURSES_VIEW_CERTIFICATES",
    "COURSES_MANAGE_CERTIFICATES",
    "COURSES_IMPORT_COURSE",
    "COURSES_EXPORT_COURSE",
    "COURSES_EXPORT_TAGS",
    "COURSES_VIEW_CHECKLISTS",
    "COURSES_MANAGE_TAGS",
    "COURSES_MANAGE_TAXONOMIES",
]

COURSES_NAMESPACE = "courses"

COURSES_VIEW_COURSE = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.view_course"),
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

COURSES_VIEW_LIBRARY_UPDATES = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.view_library_updates"),
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

COURSES_VIEW_GROUP_CONFIGURATIONS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.view_group_configurations"),
    effect="allow",
)

COURSES_MANAGE_GROUP_CONFIGURATIONS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.manage_group_configurations"),
    effect="allow",
)

COURSES_VIEW_ADVANCED_SETTINGS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.view_advanced_settings"),
    effect="allow",
)

COURSES_MANAGE_ADVANCED_SETTINGS = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.manage_advanced_settings"),
    effect="allow",
)

COURSES_VIEW_CERTIFICATES = PermissionData(
    action=ActionData(external_key=f"{COURSES_NAMESPACE}.view_certificates"),
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
