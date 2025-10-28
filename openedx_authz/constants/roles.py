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
