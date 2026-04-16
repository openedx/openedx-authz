"""Utility functions used on api"""

from django.contrib.auth import get_user_model

from openedx_authz.api.data import (
    RoleAssignmentData,
    UserAssignments,
    UserAssignmentsFilter,
)

User = get_user_model()


def get_user_map(usernames: list[str]) -> dict[str, User]:
    """
    Retrieve a dictionary mapping usernames to User objects for efficient batch lookups.

    This function performs a single optimized database query to fetch multiple users,
    making it ideal for scenarios where we need to look up several users at once
    (e.g., when serializing multiple user role assignments).

    Args:
        usernames (list[str]): List of usernames to retrieve. Duplicates are automatically
            handled by the database query.

    Returns:
        dict[str, User]: Dictionary mapping each username to its corresponding User object.
            Only users that exist in the database are included in the returned dictionary.
    """
    users = User.objects.filter(username__in=usernames, is_active=True).select_related("profile")
    return {user.username: user for user in users}


def get_user_assignment_map(role_assignments: list[RoleAssignmentData]) -> list[UserAssignments]:
    """
    Group role assignments by user
    """
    usernames = {assignment.subject.username for assignment in role_assignments}
    user_map = get_user_map(usernames)

    users_with_assignments: list[UserAssignments] = []

    for username, user in user_map.items():
        assignments = [a for a in role_assignments if a.subject.username == username]
        users_with_assignments.append(UserAssignments(user=user, assignments=assignments))

    return users_with_assignments


def filter_user_assignments(
    users_with_assignments: list[UserAssignments],
    by: UserAssignmentsFilter,
    values: list[str],
) -> list[UserAssignments]:
    """
    Filter user assignments by orgs or scopes.

    Returns a list of users that have at least one assignment matching the filters,
    with only the matching assignments for each matching user.

    Args:
        users_with_assignments (list[UserAssignments]): The list of users with their role assignments.
        by (UserAssignmentsFilter): The filter type (by orgs or scopes).
        values (list[str]): The list of orgs or scopes to filter by.

    Returns:
        list[UserAssignments]: The filtered list of users with their role assignments.
    """
    if not values:
        return users_with_assignments

    def _get_value_to_filter(assignment: RoleAssignmentData) -> str:
        if by == UserAssignmentsFilter.SCOPES:
            return assignment.scope.external_key
        elif by == UserAssignmentsFilter.ORGS:
            return getattr(assignment.scope, "org", None)
        elif by == UserAssignmentsFilter.ROLES:
            return assignment.roles[0].external_key if assignment.roles else None
        else:
            raise ValueError(f"Invalid filter: '{by}'. Must be one of {[f.value for f in UserAssignmentsFilter]}")

    filtered_users: list[UserAssignments] = []
    for uwa in users_with_assignments:
        if any(_get_value_to_filter(a) in values for a in uwa.assignments):
            # Also filter assignments to reflect the correct number of assignments
            filtered_assignments = [a for a in uwa.assignments if _get_value_to_filter(a) in values]
            filtered_users.append(UserAssignments(user=uwa.user, assignments=filtered_assignments))
    users_with_assignments = filtered_users

    return filtered_users
