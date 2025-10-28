"""
Default roles and their associated permissions.
"""

from openedx_authz.api.data import ActionData, PermissionData
from openedx_authz.constants import permissions

# Library Roles
LIBRARY_ADMIN = "library_admin"
LIBRARY_AUTHOR = "library_author"
LIBRARY_CONTRIBUTOR = "library_contributor"
LIBRARY_USER = "library_user"

LIST_LIBRARY_ADMIN_PERMISSIONS = [
    PermissionData(
        action=ActionData(external_key=permissions.VIEW_LIBRARY),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.MANAGE_LIBRARY_TAGS),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.DELETE_LIBRARY),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.EDIT_LIBRARY_CONTENT),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.PUBLISH_LIBRARY_CONTENT),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.REUSE_LIBRARY_CONTENT),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.VIEW_LIBRARY_TEAM),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.MANAGE_LIBRARY_TEAM),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.CREATE_LIBRARY_COLLECTION),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.EDIT_LIBRARY_COLLECTION),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.DELETE_LIBRARY_COLLECTION),
        effect="allow",
    ),
]

LIST_LIBRARY_AUTHOR_PERMISSIONS = [
    PermissionData(
        action=ActionData(external_key=permissions.VIEW_LIBRARY),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.MANAGE_LIBRARY_TAGS),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.EDIT_LIBRARY_CONTENT),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.PUBLISH_LIBRARY_CONTENT),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.REUSE_LIBRARY_CONTENT),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.VIEW_LIBRARY_TEAM),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.CREATE_LIBRARY_COLLECTION),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.EDIT_LIBRARY_COLLECTION),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.DELETE_LIBRARY_COLLECTION),
        effect="allow",
    ),
]

LIST_LIBRARY_CONTRIBUTOR_PERMISSIONS = [
    PermissionData(
        action=ActionData(external_key=permissions.VIEW_LIBRARY),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.MANAGE_LIBRARY_TAGS),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.EDIT_LIBRARY_CONTENT),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.REUSE_LIBRARY_CONTENT),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.VIEW_LIBRARY_TEAM),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.CREATE_LIBRARY_COLLECTION),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.EDIT_LIBRARY_COLLECTION),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.DELETE_LIBRARY_COLLECTION),
        effect="allow",
    ),
]

LIST_LIBRARY_USER_PERMISSIONS = [
    PermissionData(
        action=ActionData(external_key=permissions.VIEW_LIBRARY),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.REUSE_LIBRARY_CONTENT),
        effect="allow",
    ),
    PermissionData(
        action=ActionData(external_key=permissions.VIEW_LIBRARY_TEAM),
        effect="allow",
    ),
]
