"""Public API for roles management.

A role is named group of permissions. Instead of assigning policies to each
user, permissions can be assigned to a role, and users inherit the role's
permissions.

Casbin implements role inheritance through the g (role) and g2 (role hierarchy)
assertions.
"""

from openedx_authz.engine.enforcer import enforcer

# TODO: should we use attrs to define the Role class? Scopes and so on?
# def create_role(
#     role_name: str,
#     description: str,
#     actions: list[str],
#     resources: list[str],
#     scopes: list[str] = None,
#     context: str = None,
#     inherit_from: str = None,
# ) -> None:
#     """Create a new role in the policy store.

#     Args:
#         role_name: The name of the role.
#         description: The description of the role.
#     """
#     pass

# def add_permission_to_role(role_name: str, permission_name: str) -> None:
#     """Add a permission to a role.

#     Args:
#         role_name: The name of the role.
#         permission_name: The name of the permission.
#     """
#     pass

# def remove_permission_from_role(role_name: str, permission_name: str) -> None:
#     """Remove a permission from a role.

#     Args:
#         role_name: The name of the role.
#         permission_name: The name of the permission.
#     """
#     pass

def get_permissions_for_role(role_name: str) -> list[str]:
    """Get the permissions for a role.

    Args:
        role_name: The name of the role.
    """

def get_role_metadata(role_name: str) -> dict:
    """Get the metadata for a role.

    Args:
        role_name: The name of the role.
    """
    pass

def assign_role_to_user(user_id: str, role_name: str) -> None:
    """Assign a role to a user.

    Args:
        user_id: The ID of the user.
        role_name: The name of the role.
    """
    pass

def unassign_role_from_user(user_id: str, role_name: str) -> None:
    """Unassign a role from a user.

    Args:
        user_id: The ID of the user.
        role_name: The name of the role.
    """
    pass

def get_available_roles() -> list[str]:
    """Get the available roles.

    Returns:
        A list of available roles.
    """
    pass

def get_users_for_role(role_name: str) -> list[str]:
    """Get the users for a role.

    Args:
        role_name: The name of the role.
    """
    pass

def get_roles_for_user(user_id: str) -> list[str]:
    """Get the roles for a user.

    Args:
        user_id: The ID of the user.
    """
    pass
