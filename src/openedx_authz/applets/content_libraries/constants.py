"""Content Library permission constants."""

from openedx_authz.data import ActionData, PermissionData

__all__ = [
    "CONTENT_LIBRARIES_NAMESPACE",
    "VIEW_LIBRARY",
    "MANAGE_LIBRARY_TAGS",
    "DELETE_LIBRARY",
    "EDIT_LIBRARY_CONTENT",
    "PUBLISH_LIBRARY_CONTENT",
    "REUSE_LIBRARY_CONTENT",
    "VIEW_LIBRARY_TEAM",
    "MANAGE_LIBRARY_TEAM",
    "CREATE_LIBRARY_COLLECTION",
    "EDIT_LIBRARY_COLLECTION",
    "DELETE_LIBRARY_COLLECTION",
]

CONTENT_LIBRARIES_NAMESPACE = "content_libraries"

VIEW_LIBRARY = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.view_library"), effect="allow"
)
MANAGE_LIBRARY_TAGS = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.manage_library_tags"), effect="allow"
)
DELETE_LIBRARY = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.delete_library"), effect="allow"
)
EDIT_LIBRARY_CONTENT = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.edit_library_content"), effect="allow"
)
PUBLISH_LIBRARY_CONTENT = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.publish_library_content"), effect="allow"
)
REUSE_LIBRARY_CONTENT = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.reuse_library_content"), effect="allow"
)
VIEW_LIBRARY_TEAM = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.view_library_team"), effect="allow"
)
MANAGE_LIBRARY_TEAM = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.manage_library_team"), effect="allow"
)
CREATE_LIBRARY_COLLECTION = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.create_library_collection"), effect="allow"
)
EDIT_LIBRARY_COLLECTION = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.edit_library_collection"), effect="allow"
)
DELETE_LIBRARY_COLLECTION = PermissionData(
    action=ActionData(external_key=f"{CONTENT_LIBRARIES_NAMESPACE}.delete_library_collection"), effect="allow"
)
