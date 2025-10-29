"""
Default permission constants.
"""

from openedx_authz.api.data import ActionData, PermissionData

# Content Library Permissions
VIEW_LIBRARY = PermissionData(
    action=ActionData(external_key="view_library"),
    effect="allow",
)
MANAGE_LIBRARY_TAGS = PermissionData(
    action=ActionData(external_key="manage_library_tags"),
    effect="allow",
)
DELETE_LIBRARY = PermissionData(
    action=ActionData(external_key="delete_library"),
    effect="allow",
)
EDIT_LIBRARY_CONTENT = PermissionData(
    action=ActionData(external_key="edit_library_content"),
    effect="allow",
)
PUBLISH_LIBRARY_CONTENT = PermissionData(
    action=ActionData(external_key="publish_library_content"),
    effect="allow",
)
REUSE_LIBRARY_CONTENT = PermissionData(
    action=ActionData(external_key="reuse_library_content"),
    effect="allow",
)
VIEW_LIBRARY_TEAM = PermissionData(
    action=ActionData(external_key="view_library_team"),
    effect="allow",
)
MANAGE_LIBRARY_TEAM = PermissionData(
    action=ActionData(external_key="manage_library_team"),
    effect="allow",
)

CREATE_LIBRARY_COLLECTION = PermissionData(
    action=ActionData(external_key="create_library_collection"),
    effect="allow",
)
EDIT_LIBRARY_COLLECTION = PermissionData(
    action=ActionData(external_key="edit_library_collection"),
    effect="allow",
)
DELETE_LIBRARY_COLLECTION = PermissionData(
    action=ActionData(external_key="delete_library_collection"),
    effect="allow",
)
