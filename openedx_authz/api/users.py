"""User-related API methods for role assignments and retrievals.

This module provides user-related API methods for assigning roles to users,
unassigning roles from users, and retrieving roles assigned to users within
the Open edX AuthZ framework.

These methods internally namespace user identifiers to ensure consistency
with the role management system, which uses namespaced subjects
(e.g., 'user@john_doe').
"""

from openedx_authz.api.data import RoleData, ScopeData, SubjectData, UserData
from openedx_authz.api.roles import (
    assign_role_to_subject_in_scope,
    batch_assign_role_to_subjects_in_scope,
    batch_unassign_role_from_subjects_in_scope,
    get_subject_role_assignments,
    get_subject_role_assignments_in_scope,
    unassign_role_from_subject_in_scope,
)

__all__ = [
    "assign_role_to_user_in_scope",
    "batch_assign_role_to_users",
    "unassign_role_from_user",
    "batch_unassign_role_from_users",
    "get_user_role_assignments",
    "get_user_role_assignments_in_scope",
]


def assign_role_to_user_in_scope(username: str, role_name: str, scope_id: str) -> bool:
    """Assign a role to a user in a specific scope.

    Args:
        user (str): ID of the user (e.g., 'john_doe').
        role_name (str): Name of the role to assign.
        scope (str): Scope in which to assign the role.

    Returns:
        bool: True if the assignment was successful, False otherwise.
    """
    return assign_role_to_subject_in_scope(
        UserData(username=username),
        RoleData(name=role_name),
        ScopeData(scope_id=scope_id),
    )


def batch_assign_role_to_users(
    users: list[str], role_name: str, scope_id: str
) -> dict[str, bool]:
    """Assign a role to multiple users in a specific scope.

    Args:
        users (list of str): List of user IDs (e.g., ['john_doe', 'jane_smith']).
        role_name (str): Name of the role to assign.
        scope (str): Scope in which to assign the role.

    Returns:
        dict: A dictionary mapping user IDs to assignment success status (True/False).
    """
    namespaced_users = [UserData(username=username) for username in users]
    return batch_assign_role_to_subjects_in_scope(
        namespaced_users, RoleData(name=role_name), ScopeData(scope_id=scope_id)
    )


def unassign_role_from_user(user: str, role_name: str, scope_id: str) -> bool:
    """Unassign a role from a user in a specific scope.

    Args:
        user (str): ID of the user (e.g., 'john_doe').
        role_name (str): Name of the role to unassign.
        scope (str): Scope in which to unassign the role.

    Returns:
        bool: True if the unassignment was successful, False otherwise.
    """
    return unassign_role_from_subject_in_scope(
        UserData(username=user),
        RoleData(name=role_name),
        ScopeData(scope_id=scope_id),
    )


def batch_unassign_role_from_users(
    users: list[str], role_name: str, scope_id: str
) -> dict[str, bool]:
    """Unassign a role from multiple users in a specific scope.

    Args:
        users (list of str): List of user IDs (e.g., ['john_doe', 'jane_smith']).
        role_name (str): Name of the role to unassign.
        scope (str): Scope in which to unassign the role.

    Returns:
        dict: A dictionary mapping user IDs to unassignment success status (True/False).
    """
    namespaced_users = [UserData(username=user) for user in users]
    return batch_unassign_role_from_subjects_in_scope(
        namespaced_users, RoleData(name=role_name), ScopeData(scope_id=scope_id)
    )


def get_user_role_assignments(username: str) -> list[dict]:
    """Get all roles for a user across all scopes.

    Args:
        user (str): ID of the user (e.g., 'john_doe').

    Returns:
        list[dict]: A list of role names and all their metadata assigned to the user.
    """
    return get_subject_role_assignments(UserData(username=username))


def get_user_role_assignments_in_scope(username: str, scope_id: str) -> list[str]:
    """Get the roles assigned to a user in a specific scope.

    Args:
        user (str): ID of the user (e.g., 'john_doe').
        scope (str): Scope in which to retrieve the roles.

    Returns:
        list: A list of role names assigned to the user in the specified scope.
    """
    return get_subject_role_assignments_in_scope(
        UserData(username=username), ScopeData(scope_id=scope_id)
    )
