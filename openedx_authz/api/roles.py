"""Public API for roles management.

A role is named group of permissions. Instead of assigning policies to each
user, permissions can be assigned to a role, and users inherit the role's
permissions.

Casbin implements role inheritance through the g (role) and g2 (role hierarchy)
assertions.
"""

from typing import Literal

from attrs import define

# from openedx_authz.engine.enforcer import enforcer
# TODO: should we dependency inject the enforcer to the API functions?
# For now, we create a global enforcer instance for testing purposes
from openedx_authz.engine.enforcer import enforcer


@define
class Permission:  # TODO: change to policy?
    """A permission is an action that can be performed under certain conditions.

    Attributes:
        name: The name of the permission.
    """

    # TODO: what other attributes should a permission have?
    name: str
    effect: Literal["allow", "deny"] = "allow"


@define
class Role:
    """A role is a named group of permissions.

    Attributes:
        name: The name of the role.
        permissions: A list of permissions assigned to the role.
        scopes: A list of scopes assigned to the role.
        metadata: A dictionary of metadata assigned to the role. This can include
            information such as the description of the role, creation date, etc.
    """

    name: str
    permissions: list[Permission] = None
    scopes: list[str] = None
    metadata: dict[str, str] = None


def create_role_in_scope_and_assign_permissions(role_name: str, permissions: list[Permission], scope: str) -> None:
    """Create a role and assign permissions to it.

    Args:
        role_name: The name of the role.
        permissions: A list of permissions to assign to the role.
        scope: The scope in which to create the role.
    """
    for permission in permissions:
        enforcer.add_policy(role_name, permission.name, scope, permission.effect)


def get_permissions_for_roles(role_names: list[str]) -> dict[str, list[Permission]]:
    """Get the permissions for a list of roles.

    A permission is a policy rule with the effect 'allow' assigned to a role.

    Args:
        role_names: A list of role names.

    Returns:
        dict[str, list[Permission]]: A dictionary mapping role names to a list of permissions.
    """
    # TODO: do I need to return implicit permissions as well?
    # TODO: This considers that there is no inheritance between roles
    # TODO: should we say policies instead of permissions?
    permissions_by_role = {}
    for role_name in role_names:
        permissions = enforcer.get_permissions_for_user(role_name)
        permissions_by_role[role_name] = [
            Permission(name=perm[1], effect=perm[3]) for perm in permissions
        ]
    return permissions_by_role


def assign_role_to_user_in_scope(username: str, role_name: str, scope: str) -> None:
    """Assign a role to a user.

    Args:
        username: The ID of the user.
        role_name: The name of the role.
        scope: The scope in which to assign the role.
    """
    return enforcer.add_role_for_user_in_domain(username, role_name, scope)


def unassign_role_from_user_in_scope(username: str, role_name: str, scope: str) -> None:
    """Unassign a role from a user.

    Args:
        username: The ID of the user.
        role_name: The name of the role.
        scope: The scope from which to unassign the role.
    """
    return enforcer.remove_role_for_user_in_domain(username, role_name, scope)


def get_all_roles() -> list[Role]:
    """Get all the available roles in the current environment.

    Returns:
        list[Role]: A list of role names and all their metadata.
    """
    return enforcer.get_all_subjects()


def get_roles_in_scope(scope: str) -> list[Role]:
    """Get the available roles for the current environment.

    In this case, we return all the roles defined in the policy file that
    match the given scope.

    Args:
        scope: The scope to filter roles (e.g., 'library:123' or '*' for global).

    Returns:
        list[Role]: A list of roles available in the specified scope.
    """
    return enforcer.get_all_roles_by_domain(scope)


def get_roles_for_user_in_scope(username: str, scope: str) -> list[Role]:
    """Get the roles for a user.

    Args:
        username: The ID of the user namespaced (e.g., 'user:john_doe').

    Returns:
        list[Role]: A list of role names and all their metadata assigned to the user.
    """
    return enforcer.get_roles_for_user_in_domain(username, scope)


def get_users_for_role_in_scope(role_name: str, scope: str) -> list[str]:
    """Get the users for a role.

    Args:
        role_name: The name of the role.

    Returns:
        list[str]: A list of user IDs (usernames) assigned to the role.
    """
    return enforcer.get_users_for_role_in_domain(role_name, scope)
