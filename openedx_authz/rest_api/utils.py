"""Utility functions for the Open edX AuthZ REST API."""

import threading

from django.contrib.auth import get_user_model
from django.db.models import Q

from openedx_authz.api.data import GENERIC_SCOPE_WILDCARD, ScopeData
from openedx_authz.rest_api.data import SearchField, SortField, SortOrder

User = get_user_model()


_user_cache_local = threading.local()


def get_generic_scope(scope: ScopeData) -> ScopeData:
    """
    Create a generic scope from a given scope by replacing its key with a wildcard.

    This function preserves the namespace of the original scope but replaces the specific
    key with a wildcard, allowing for broader permission checks across all scopes within
    the same namespace.

    Args:
        scope (ScopeData): The specific scope to generalize.

    Returns:
        ScopeData: A new scope with the same namespace but a wildcard key.

    Examples:
        >>> scope = ScopeData(namespaced_key="lib^lib:DemoX:CSPROB")
        >>> get_generic_scope(scope)
        ScopeData(namespaced_key="lib^*")
    """
    return ScopeData(namespaced_key=f"{scope.NAMESPACE}{ScopeData.SEPARATOR}{GENERIC_SCOPE_WILDCARD}")


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
    users = User.objects.filter(username__in=usernames).select_related("profile")
    return {user.username: user for user in users}


def get_user_by_username_or_email(username_or_email: str) -> User:
    """
    Retrieve a user by their username or email address with thread-local caching.

    This function performs a flexible user lookup that accepts either a username or email
    address and returns the corresponding User object. Results are cached per-thread to
    avoid redundant database queries when the same user is looked up multiple times within
    the same request or thread context.

    Args:
        username_or_email (str): The username or email address to search for. The function
            will query both fields and return the first matching user.

    Returns:
        User: The User object matching the provided username or email address.

    Raises:
        User.DoesNotExist: If no user is found with the given username or email, or if
            the user has been retired (has an associated userretirementrequest).

    Note:
        - Uses thread-local storage for caching, so cache is isolated per thread/request
        - Negative lookups (non-existent users) are also cached to prevent repeated queries
        - Cache persists for the lifetime of the thread and is automatically cleaned up
        - Retired users (with userretirementrequest) are treated as non-existent
    """
    cache = getattr(_user_cache_local, "data", None)
    if cache is None:
        cache = {}
        _user_cache_local.data = cache

    if username_or_email not in cache:
        try:
            user = User.objects.get(Q(email=username_or_email) | Q(username=username_or_email))
            if hasattr(user, "userretirementrequest"):
                raise User.DoesNotExist
            cache[username_or_email] = user
        except User.DoesNotExist:
            cache[username_or_email] = None

    user = cache[username_or_email]
    if user is None:
        raise User.DoesNotExist
    return user


def sort_users(
    users: list[dict],
    sort_by: SortField = SortField.USERNAME,
    order: SortOrder = SortOrder.ASC,
) -> list[dict]:
    """
    Sort users by a given field and order.

    Args:
        users (list[dict]): The users to sort.
        sort_by (SortField, optional): The field to sort by. Defaults to SortField.USERNAME.
        order (SortOrder, optional): The order to sort by. Defaults to SortOrder.ASC.

    Raises:
        ValueError: If the sort field is invalid.
        ValueError: If the sort order is invalid.

    Returns:
        list[dict]: The sorted users.
    """
    if sort_by not in SortField.values():
        raise ValueError(f"Invalid field: '{sort_by}'. Must be one of {SortField.values()}")

    if order not in SortOrder.values():
        raise ValueError(f"Invalid order: '{order}'. Must be one of {SortOrder.values()}")

    sorted_users = sorted(
        users,
        key=lambda user: (user.get(sort_by) or "").lower(),
        reverse=order == SortOrder.DESC,
    )
    return sorted_users


def filter_users(users: list[dict], search: str | None, roles: list[str] | None) -> list[dict]:
    """
    Filter users by a case-insensitive search string and/or by roles.

    Args:
        users (list[dict]): The users to filter.
        search (str | None): Optional search term matched against fields in ``SearchField``.
        roles (list[str] | None): Optional list of roles; include users that have any of these roles.

    Returns:
        list[dict]: The filtered users, preserving the original order.
    """
    if not search and not roles:
        return users

    filtered_users = []
    for user in users:
        if search:
            matches_search = any(search in (user.get(field) or "").lower() for field in SearchField.values())
            if not matches_search:
                continue

        if roles:
            matches_role = any(role in user.get("roles", []) for role in roles)
            if not matches_role:
                continue

        filtered_users.append(user)

    return filtered_users
