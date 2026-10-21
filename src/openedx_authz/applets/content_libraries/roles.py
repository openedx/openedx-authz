"""Content Library role constants.

Each constant identifies a role. Its permissions are defined in ``schema/roles.yaml``.
"""

from openedx_authz.api.data import RoleData

LIBRARY_ADMIN = RoleData(external_key="library_admin")
LIBRARY_AUTHOR = RoleData(external_key="library_author")
LIBRARY_CONTRIBUTOR = RoleData(external_key="library_contributor")
LIBRARY_USER = RoleData(external_key="library_user")

__all__ = [
    "LIBRARY_ADMIN",
    "LIBRARY_AUTHOR",
    "LIBRARY_CONTRIBUTOR",
    "LIBRARY_USER",
]
