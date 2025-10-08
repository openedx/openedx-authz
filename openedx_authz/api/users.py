"""User-related API methods for role assignments and retrievals.

This module provides user-related API methods for assigning roles to users,
unassigning roles from users, and retrieving roles assigned to users within
the Open edX AuthZ framework.

These methods internally namespace user identifiers to ensure consistency
with the role management system, which uses namespaced subjects
(e.g., 'user^john_doe').
"""

from openedx_authz.api.data import ActionData, RoleAssignmentData, RoleData, ScopeData, UserData
from openedx_authz.api.permissions import is_subject_allowed
from openedx_authz.api.roles import (
    assign_role_to_subject_in_scope,
    batch_assign_role_to_subjects_in_scope,
    batch_unassign_role_from_subjects_in_scope,
    get_all_subject_role_assignments_in_scope,
    get_subject_role_assignments,
    get_subject_role_assignments_for_role_in_scope,
    get_subject_role_assignments_in_scope,
    get_subjects_for_role,
    unassign_role_from_subject_in_scope,
)

__all__ = [
    "assign_role_to_user_in_scope",
    "batch_assign_role_to_users_in_scope",
    "unassign_role_from_user",
    "batch_unassign_role_from_users",
    "get_user_role_assignments",
    "get_user_role_assignments_in_scope",
    "get_user_role_assignments_for_role_in_scope",
    "get_all_user_role_assignments_in_scope",
    "is_user_allowed",
    "get_users_for_role",
]


def assign_role_to_user_in_scope(user_external_key: str, role_external_key: str, scope_external_key: str) -> bool:
    """Assign a role to a user in a specific scope.

    Args:
        user (str): ID of the user (e.g., 'john_doe').
        role_external_key (str): Name of the role to assign.
        scope (str): Scope in which to assign the role.

    Returns:
        bool: True if the role was assigned successfully, False otherwise.
    """
    return assign_role_to_subject_in_scope(
        UserData(external_key=user_external_key),
        RoleData(external_key=role_external_key),
        ScopeData(external_key=scope_external_key),
    )


def batch_assign_role_to_users_in_scope(users: list[str], role_external_key: str, scope_external_key: str):
    """Assign a role to multiple users in a specific scope.

    Args:
        users (list of str): List of user IDs (e.g., ['john_doe', 'jane_smith']).
        role_external_key (str): Name of the role to assign.
        scope (str): Scope in which to assign the role.
    """
    namespaced_users = [UserData(external_key=username) for username in users]
    batch_assign_role_to_subjects_in_scope(
        namespaced_users,
        RoleData(external_key=role_external_key),
        ScopeData(external_key=scope_external_key),
    )


def unassign_role_from_user(user_external_key: str, role_external_key: str, scope_external_key: str):
    """Unassign a role from a user in a specific scope.

    Args:
        user_external_key (str): ID of the user (e.g., 'john_doe').
        role_external_key (str): Name of the role to unassign.
        scope_external_key (str): Scope in which to unassign the role.

    Returns:
        bool: True if the role was unassigned successfully, False otherwise.
    """
    return unassign_role_from_subject_in_scope(
        UserData(external_key=user_external_key),
        RoleData(external_key=role_external_key),
        ScopeData(external_key=scope_external_key),
    )


def batch_unassign_role_from_users(users: list[str], role_external_key: str, scope_external_key: str):
    """Unassign a role from multiple users in a specific scope.

    Args:
        users (list of str): List of user IDs (e.g., ['john_doe', 'jane_smith']).
        role_external_key (str): Name of the role to unassign.
        scope (str): Scope in which to unassign the role.
    """
    namespaced_users = [UserData(external_key=user) for user in users]
    batch_unassign_role_from_subjects_in_scope(
        namespaced_users,
        RoleData(external_key=role_external_key),
        ScopeData(external_key=scope_external_key),
    )


def get_user_role_assignments(user_external_key: str) -> list[RoleAssignmentData]:
    """Get all roles for a user across all scopes.

    Args:
        user_external_key (str): ID of the user (e.g., 'john_doe').

    Returns:
        list[RoleAssignmentData]: A list of role assignments and all their metadata assigned to the user.
    """
    return get_subject_role_assignments(UserData(external_key=user_external_key))


def get_user_role_assignments_in_scope(user_external_key: str, scope_external_key: str) -> list[RoleAssignmentData]:
    """Get the roles assigned to a user in a specific scope.

    Args:
        user (str): ID of the user (e.g., 'john_doe').
        scope (str): Scope in which to retrieve the roles.

    Returns:
        list[RoleAssignmentData]: A list of role assignments assigned to the user in the specified scope.
    """
    return get_subject_role_assignments_in_scope(
        UserData(external_key=user_external_key),
        ScopeData(external_key=scope_external_key),
    )


def get_user_role_assignments_for_role_in_scope(
    role_external_key: str, scope_external_key: str
) -> list[RoleAssignmentData]:
    """Get all users assigned to a specific role across all scopes.

    Args:
        role_external_key (str): Name of the role (e.g., 'instructor').
        scope (str): Scope in which to retrieve the role assignments.

    Returns:
        list[RoleAssignmentData]: List of users assigned to the specified role in the given scope.
    """
    return get_subject_role_assignments_for_role_in_scope(
        RoleData(external_key=role_external_key),
        ScopeData(external_key=scope_external_key),
    )


def get_all_user_role_assignments_in_scope(
    scope_external_key: str,
) -> list[RoleAssignmentData]:
    """Get all user role assignments in a specific scope.

    Args:
        scope (str): Scope in which to retrieve the user role assignments.

    Returns:
        list[RoleAssignmentData]: A list of user role assignments and all their metadata in the specified scope.
    """
    return get_all_subject_role_assignments_in_scope(ScopeData(external_key=scope_external_key))


def is_user_allowed(
    user_external_key: str,
    action_external_key: str,
    scope_external_key: str,
) -> bool:
    """Check if a user has a specific permission in a given scope.

    Args:
        user_external_key (str): ID of the user (e.g., 'john_doe').
        action_external_key (str): The action to check (e.g., 'view_course').
        scope_external_key (str): The scope in which to check the permission (e.g., 'course-v1:edX+DemoX+2021_T1').

    Returns:
        bool: True if the user has the specified permission in the scope, False otherwise.
    """
    return is_subject_allowed(
        UserData(external_key=user_external_key),
        ActionData(external_key=action_external_key),
        ScopeData(external_key=scope_external_key),
    )


def get_users_for_role(role_external_key: str) -> list[UserData]:
    """Get all the users assigned to a specific role.

    Args:
        role_external_key (str): The role to filter users (e.g., 'library_admin').

    Returns:
        list[UserData]: A list of users assigned to the specified role.
    """
    users = get_subjects_for_role(RoleData(external_key=role_external_key))
    return [UserData(namespaced_key=user.namespaced_key) for user in users]
