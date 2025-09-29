"""User-related API methods for role assignments and retrievals.

This module provides user-related API methods for assigning roles to users,
unassigning roles from users, and retrieving roles assigned to users within
the Open edX AuthZ framework.

These methods internally namespace user identifiers to ensure consistency
with the role management system, which uses namespaced subjects
(e.g., 'user:john_doe').
"""

from openedx_authz.api.roles import (
    assign_role_to_user_in_scope,
    batch_assign_role_to_subjects_in_scope,
    batch_unassign_role_from_subjects_in_scope,
    get_roles_for_subject,
    get_roles_for_subject_in_scope,
    unassign_role_from_subject_in_scope,
)


def assign_role_to_user(user: str, role_name: str, scope: str) -> bool:
    """Assign a role to a user in a specific scope.

    Args:
        user (str): ID of the user (e.g., 'john_doe').
        role_name (str): Name of the role to assign.
        scope (str): Scope in which to assign the role.

    Returns:
        bool: True if the assignment was successful, False otherwise.
    """
    namespaced_user = f"user:{user}"
    return assign_role_to_user_in_scope(namespaced_user, role_name, scope)


def batch_assign_role_to_users(
    users: list[str], role_name: str, scope: str
) -> dict[str, bool]:
    """Assign a role to multiple users in a specific scope.

    Args:
        users (list of str): List of user IDs (e.g., ['john_doe', 'jane_smith']).
        role_name (str): Name of the role to assign.
        scope (str): Scope in which to assign the role.

    Returns:
        dict: A dictionary mapping user IDs to assignment success status (True/False).
    """
    namespaced_users = [f"user:{user}" for user in users]
    return batch_assign_role_to_subjects_in_scope(namespaced_users, role_name, scope)


def unassign_role_from_user(user: str, role_name: str, scope: str) -> bool:
    """Unassign a role from a user in a specific scope.

    Args:
        user (str): ID of the user (e.g., 'john_doe').
        role_name (str): Name of the role to unassign.
        scope (str): Scope in which to unassign the role.

    Returns:
        bool: True if the unassignment was successful, False otherwise.
    """
    namespaced_user = f"user:{user}"
    return unassign_role_from_subject_in_scope(
        [namespaced_user], role_name, scope, batch=False
    ).get(user, False)


def batch_unassign_role_from_users(
    users: list[str], role_name: str, scope: str
) -> dict[str, bool]:
    """Unassign a role from multiple users in a specific scope.

    Args:
        users (list of str): List of user IDs (e.g., ['john_doe', 'jane_smith']).
        role_name (str): Name of the role to unassign.
        scope (str): Scope in which to unassign the role.

    Returns:
        dict: A dictionary mapping user IDs to unassignment success status (True/False).
    """
    namespaced_users = [f"user:{user}" for user in users]
    return batch_unassign_role_from_subjects_in_scope(
        namespaced_users, role_name, scope
    )


def get_roles_for_user(user: str, include_permissions: bool = True) -> list[dict]:
    """Get all roles with metadata assigned to a user in a specific scope.

    Args:
        user (str): ID of the user (e.g., 'john_doe').
        include_permissions (bool): True by default. If True, include
        permissions in the role metadata.

    Returns:
        list[dict]: A list of role names and all their metadata assigned to the user.
    """
    namespaced_user = f"user:{user}"
    return get_roles_for_subject(namespaced_user, include_permissions)


def get_roles_for_user_in_scope(user: str, scope: str) -> list[str]:
    """Get the roles assigned to a user in a specific scope.

    Args:
        user (str): ID of the user (e.g., 'john_doe').
        scope (str): Scope in which to retrieve the roles.

    Returns:
        list: A list of role names assigned to the user in the specified scope.
    """
    namespaced_user = f"user:{user}"
    return get_roles_for_subject_in_scope(namespaced_user, scope)
