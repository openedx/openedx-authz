"""Utility functions used on api"""

import logging
import operator
from functools import reduce

from django.contrib.auth import get_user_model
from django.db.models import Q

from openedx_authz.api.data import (
    ContentLibraryData,
    CourseOverviewData,
    RoleAssignmentData,
    ScopeData,
    UserAssignments,
)
from openedx_authz.models.scopes import get_content_library_model, get_course_overview_model

log = logging.getLogger(__name__)

User = get_user_model()
ContentLibrary = get_content_library_model()
CourseOverview = get_course_overview_model()


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


def get_scope_display_name_map(scope_external_keys: set[str]) -> dict[str, str]:
    """Build a mapping of scope external keys to their display names.

    Accepts a set of scope external key strings, partitions them into library
    and course scopes via :class:`ScopeData`, batch-queries the ContentLibrary
    and CourseOverview models, and returns a single dict that maps each key to
    its human-readable display name.

    Glob scopes (org-level and platform-level wildcards) are skipped because
    they don't correspond to a single DB record.

    Args:
        scope_external_keys: The scope external key strings to resolve.

    Returns:
        A dict mapping scope external_key strings to display name strings.
        Scopes that could not be resolved (e.g. glob patterns, missing DB
        records, or unregistered keys) are omitted from the result.
    """
    display_name_map: dict[str, str] = {}

    # Partition concrete (non-glob) scopes by type.
    library_scopes: list[ContentLibraryData] = []
    course_scope_keys: set[str] = set()

    for key in scope_external_keys:
        try:
            scope = ScopeData(external_key=key)
        except ValueError:
            continue
        if scope.IS_GLOB:
            continue
        if isinstance(scope, ContentLibraryData):
            library_scopes.append(scope)
        elif isinstance(scope, CourseOverviewData):
            course_scope_keys.add(scope.external_key)

    # Batch-query ContentLibrary display names.
    if library_scopes and ContentLibrary is not None:
        lib_pairs = {(s.library_key.org, s.library_key.slug) for s in library_scopes}
        try:
            lib_filter = reduce(
                operator.or_, (Q(org__short_name=org, slug=slug) for org, slug in lib_pairs)
            )
            lib_qs = ContentLibrary.objects.filter(lib_filter).select_related("learning_package", "org")

            for lib in lib_qs:
                external_key = f"lib:{lib.org.short_name}:{lib.slug}"
                display_name_map[external_key] = getattr(lib.learning_package, "title", "") or ""
        except Exception:  # pylint: disable=broad-exception-caught
            log.exception("Failed to fetch ContentLibrary display names")

    # Batch-query CourseOverview display names.
    if course_scope_keys and CourseOverview is not None:
        try:
            course_qs = CourseOverview.objects.filter(id__in=course_scope_keys)
            for course in course_qs:
                display_name_map[str(course.id)] = course.display_name or ""
        except Exception:  # pylint: disable=broad-exception-caught
            log.exception("Failed to fetch CourseOverview display names")

    return display_name_map
