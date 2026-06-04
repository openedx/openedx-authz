"""Utility functions used on api"""

from django.contrib.auth import get_user_model

from openedx_authz.api.data import (
    RoleAssignmentData,
    UserAssignments,
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
