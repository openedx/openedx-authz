"""Expected permissions for built-in roles, as defined in the applets' YAML schema files."""

from openedx_authz.constants import permissions

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

COURSE_AUDITOR_PERMISSIONS = [
    permissions.COURSES_VIEW_COURSE,
    permissions.COURSES_VIEW_COURSE_UPDATES,
    permissions.COURSES_VIEW_PAGES_AND_RESOURCES,
    permissions.COURSES_VIEW_FILES,
    permissions.COURSES_VIEW_GRADING_SETTINGS,
    permissions.COURSES_VIEW_CHECKLISTS,
    permissions.COURSES_VIEW_COURSE_TEAM,
    permissions.COURSES_VIEW_SCHEDULE_AND_DETAILS,
    permissions.COURSES_VIEW_ADVANCED_SETTINGS,
    permissions.COURSES_VIEW_CERTIFICATES,
    permissions.COURSES_VIEW_GROUP_CONFIGURATIONS,
    permissions.COURSES_VIEW_LIBRARY_UPDATES,
]
