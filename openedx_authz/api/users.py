"""User-related API methods for role assignments and retrievals.

This module provides user-related API methods for assigning roles to users,
unassigning roles from users, and retrieving roles assigned to users within
the Open edX AuthZ framework.

These methods internally namespace user identifiers to ensure consistency
with the role management system, which uses namespaced subjects
(e.g., 'user^john_doe').
"""

from django.contrib.auth import get_user_model

from openedx_authz.api.data import (
    ActionData,
    PermissionData,
    RoleAssignmentData,
    RoleData,
    ScopeData,
    UserAssignments,
    UserAssignmentsFilter,
    UserData,
)
from openedx_authz.api.permissions import is_subject_allowed
from openedx_authz.api.roles import (
    assign_role_to_subject_in_scope,
    batch_assign_role_to_subjects_in_scope,
    batch_unassign_role_from_subjects_in_scope,
    get_all_subject_role_assignments_in_scope,
    get_role_assignments,
    get_scopes_for_subject_and_permission,
    get_subject_role_assignments,
    get_subject_role_assignments_for_role_in_scope,
    get_subject_role_assignments_in_scope,
    get_subjects_for_role_in_scope,
    unassign_role_from_subject_in_scope,
    unassign_subject_from_all_roles,
)
from openedx_authz.api.utils import filter_user_assignments, get_user_assignment_map
from openedx_authz.utils import get_user_by_username_or_email

__all__ = [
    "assign_role_to_user_in_scope",
    "batch_assign_role_to_users_in_scope",
    "unassign_role_from_user",
    "batch_unassign_role_from_users",
    "get_user_role_assignments",
    "get_user_role_assignments_in_scope",
    "get_user_role_assignments_for_role_in_scope",
    "get_user_role_assignments_filtered",
    "get_all_user_role_assignments_in_scope",
    "get_visible_role_assignments_for_user",
    "is_user_allowed",
    "get_scopes_for_user_and_permission",
    "get_users_for_role_in_scope",
    "unassign_all_roles_from_user",
    "validate_users",
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


def get_user_role_assignments_filtered(
    *,
    user_external_key: str | None = None,
    role_external_key: str | None = None,
    scope_external_key: str | None = None,
) -> list[RoleAssignmentData]:
    """Get role assignments filtered by user, role, and/or scope.

    This function provides flexible filtering of role assignments by any combination
    of user, role, and scope. At least one filter parameter should be provided for
    meaningful results.

    Args:
        user_external_key: Optional user ID to filter by (e.g., 'john_doe').
        role_external_key: Optional role name to filter by (e.g., 'library_admin').
        scope_external_key: Optional scope to filter by (e.g., 'lib:DemoX:CSPROB').

    Returns:
        list[RoleAssignmentData]: Filtered role assignments.
    """
    return get_role_assignments(
        subject=UserData(external_key=user_external_key) if user_external_key else None,
        role=RoleData(external_key=role_external_key) if role_external_key else None,
        scope=ScopeData(external_key=scope_external_key) if scope_external_key else None,
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


def _filter_allowed_assignments(
    user_external_key: str, assignments: list[RoleAssignmentData]
) -> list[RoleAssignmentData]:
    """
    Filter the given role assignments to only include those that the user has permission to view.
    """
    allowed_assignments: list[RoleAssignmentData] = []
    for assignment in assignments:
        permission = None

        # Get the permission needed to view the specific scope in the admin console
        permission = assignment.scope.get_admin_view_permission().identifier

        if permission and is_user_allowed(
            user_external_key=user_external_key,
            action_external_key=permission,
            scope_external_key=assignment.scope.external_key,
        ):
            allowed_assignments.append(assignment)

    return allowed_assignments


def get_visible_role_assignments_for_user(
    orgs: list[str] = None,
    scopes: list[str] = None,
    allowed_for_user_external_key: str = None,
) -> list[UserAssignments]:
    """
    Get all user role assignments filtered by orgs and/or scopes, and only include
    assignments that the specified user has permission to view.

    Args:
        orgs: Optional list of orgs to filter by (e.g., ['edX', 'MITx']).
        scopes: Optional list of scopes to filter by (e.g., ['lib:DemoX:CSPROB']).
        allowed_for_user_external_key: The username to check permissions against (e.g., 'john_doe').

    Returns:
        list[UserAssignments]: A list of users with their role assignments, filtered by orgs/scopes and permissions.
    """
    user_role_assignments = get_user_role_assignments_filtered()
    # Filter assignments based on the user's permissions
    user_role_assignments = _filter_allowed_assignments(
        user_external_key=allowed_for_user_external_key,
        assignments=user_role_assignments,
    )
    # Group assignments by user
    users_with_assignments = get_user_assignment_map(user_role_assignments)

    users_with_assignments = filter_user_assignments(
        users_with_assignments=users_with_assignments,
        by=UserAssignmentsFilter.SCOPES,
        values=scopes,
    )
    users_with_assignments = filter_user_assignments(
        users_with_assignments=users_with_assignments,
        by=UserAssignmentsFilter.ORGS,
        values=orgs,
    )
    return users_with_assignments


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


def get_users_for_role_in_scope(role_external_key: str, scope_external_key: str) -> list[UserData]:
    """Get all the users assigned to a specific role in a specific scope.

    Args:
        role_external_key (str): The role to filter users (e.g., 'library_admin').
        scope_external_key (str): The scope to filter users (e.g., 'lib:DemoX:CSPROB').

    Returns:
        list[UserData]: A list of users assigned to the specified role in the specified scope.
    """
    users = get_subjects_for_role_in_scope(
        RoleData(external_key=role_external_key),
        ScopeData(external_key=scope_external_key),
    )
    return [UserData(namespaced_key=user.namespaced_key) for user in users]


def get_scopes_for_user_and_permission(
    user_external_key: str,
    action_external_key: str,
) -> list[ScopeData]:
    """Get all scopes where a specific user is assigned a specific permission.

    Args:
        user_external_key (str): ID of the user (e.g., 'john_doe').
        action_external_key (str): The action to filter scopes (e.g., 'view', 'edit').

    Returns:
        list[ScopeData]: A list of scopes where the user is assigned the specified permission.
    """
    return get_scopes_for_subject_and_permission(
        UserData(external_key=user_external_key),
        PermissionData(action=ActionData(external_key=action_external_key)),
    )


def unassign_all_roles_from_user(user_external_key: str) -> bool:
    """Unassign all roles from a user across all scopes.

    Args:
        user_external_key (str): ID of the user (e.g., 'john_doe').

    Returns:
        bool: True if any roles were removed, False otherwise.
    """
    return unassign_subject_from_all_roles(UserData(external_key=user_external_key))


def validate_users(user_identifiers: list[str]) -> tuple[list[str], list[str]]:
    """Validate a list of user identifiers.

    Args:
        user_identifiers (list[str]): List of usernames or emails to validate

    Returns:
        tuple: (valid_users, invalid_users) lists
    """
    User = get_user_model()
    valid_users = []
    invalid_users = []

    for user_identifier in user_identifiers:
        try:
            user = get_user_by_username_or_email(user_identifier)
            if user.is_active:
                valid_users.append(user_identifier)
            else:
                invalid_users.append(user_identifier)
        except User.DoesNotExist:
            invalid_users.append(user_identifier)

    return valid_users, invalid_users
