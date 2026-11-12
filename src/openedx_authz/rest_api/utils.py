"""Utility functions for the Open edX AuthZ REST API."""

from datetime import datetime

from openedx_authz.api.data import (
    GLOBAL_SCOPE_WILDCARD,
    ScopeData,
)
from openedx_authz.api.utils import get_scope_display_name_map
from openedx_authz.rest_api.data import (
    AssignmentSortField,
    BaseEnum,
    RoleSortField,
    ScopesTypeField,
    SearchField,
    SerializedAssignment,
    SortField,
    SortOrder,
    UserAssignmentSortField,
)


def parse_scope_types(value: str | None) -> list[str] | None:
    """Parse a comma-separated ``scope_types`` query value.

    Args:
        value: The raw query value (e.g., 'course-v1,lib'), or None if it was not provided.

    Returns:
        list[str] | None: The unique scope types in request order, or None if the value is missing,
            has an empty item or has an item that is not a supported scope type.
    """
    if not value:
        return None
    items = [item.strip() for item in value.split(",")]
    if any(item not in ScopesTypeField.values() for item in items):
        return None
    return list(dict.fromkeys(items))


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
    return ScopeData(namespaced_key=f"{scope.NAMESPACE}{ScopeData.SEPARATOR}{GLOBAL_SCOPE_WILDCARD}")


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


def _sort_by_field(
    items: list[dict],
    sort_by: str,
    order: str,
    allowed_fields: type[BaseEnum],
) -> list[dict]:
    """
    Sort a list of dicts by a given field and order, validating against the provided enum.

    Args:
        items (list[dict]): The items to sort.
        sort_by (str): The field to sort by.
        order (str): The order to sort by.
        allowed_fields (type[BaseEnum]): The enum class whose values are the valid sort fields.

    Raises:
        ValueError: If the sort field is invalid.
        ValueError: If the sort order is invalid.

    Returns:
        list[dict]: The sorted items.
    """
    if sort_by not in allowed_fields.values():
        raise ValueError(f"Invalid field: '{sort_by}'. Must be one of {allowed_fields.values()}")

    if order not in SortOrder.values():
        raise ValueError(f"Invalid order: '{order}'. Must be one of {SortOrder.values()}")

    return sorted(
        items,
        key=lambda item: (item.get(sort_by) or "").lower(),
        reverse=order == SortOrder.DESC,
    )


def sort_assignments(
    assignments: list[dict],
    sort_by: AssignmentSortField = AssignmentSortField.ROLE,
    order: SortOrder = SortOrder.ASC,
) -> list[dict]:
    """
    Sort role assignments by a given field and order.

    Args:
        assignments (list[dict]): The assignments to sort.
        sort_by (AssignmentSortField, optional): The field to sort by. Defaults to AssignmentSortField.ROLE.
        order (SortOrder, optional): The order to sort by. Defaults to SortOrder.ASC.

    Raises:
        ValueError: If the sort field is invalid.
        ValueError: If the sort order is invalid.

    Returns:
        list[dict]: The sorted assignments.
    """
    return _sort_by_field(assignments, sort_by, order, AssignmentSortField)


def sort_user_assignments(
    assignments: list[dict],
    sort_by: UserAssignmentSortField = UserAssignmentSortField.ROLE,
    order: SortOrder = SortOrder.ASC,
) -> list[dict]:
    """
    Sort role assignments by a given field and order.

    Args:
        assignments (list[dict]): The assignments to sort.
        sort_by (UserAssignmentSortField, optional): The field to sort by. Defaults to UserAssignmentSortField.ROLE.
        order (SortOrder, optional): The order to sort by. Defaults to SortOrder.ASC.

    Raises:
        ValueError: If the sort field is invalid.
        ValueError: If the sort order is invalid.

    Returns:
        list[dict]: The sorted assignments.
    """
    return _sort_by_field(assignments, sort_by, order, UserAssignmentSortField)


def filter_roles(roles: list[dict], search: str | None, definition_kind: str | None) -> list[dict]:
    """Filter role catalog entries by display name and definition kind.

    Runs in Python, not in the database, because static role names are translated with gettext
    and the search has to match the name the user sees.

    Args:
        roles (list[dict]): Role catalog entries, as returned by ``get_role_catalog``.
        search (str | None): Optional case-insensitive substring of ``display_name``.
        definition_kind (str | None): Optional ``DefinitionKind`` value to keep.

    Returns:
        list[dict]: The matching roles, preserving the original order.
    """
    if not search and not definition_kind:
        return roles

    search = search.lower() if search else None
    return [
        role
        for role in roles
        if (not search or search in (role.get("display_name") or "").lower())
        and (not definition_kind or role.get("definition_kind") == definition_kind)
    ]


def _role_sort_value(role: dict, sort_by: str) -> str | int | datetime | None:
    """Return the value of a role to sort by, or None when the role has no value for the field."""
    if sort_by == RoleSortField.DISPLAY_NAME:
        return (role.get("display_name") or "").lower()
    if sort_by == RoleSortField.SCOPE_TYPE:
        return ",".join(role.get("scope_types") or [])
    if sort_by == RoleSortField.USER_COUNT:
        return role.get("user_count") or 0
    return role.get("updated_at")


def sort_roles(
    roles: list[dict],
    sort_by: RoleSortField = RoleSortField.DISPLAY_NAME,
    order: SortOrder = SortOrder.ASC,
) -> list[dict]:
    """Sort role catalog entries by a field and order.

    Unlike :func:`_sort_by_field`, the values are not all strings: ``user_count`` sorts as a
    number and ``updated_at`` as a date. Roles without a value (``updated_at`` of static roles)
    go last in both orders, so a descending sort still starts with the most recently updated
    role. Ties are broken by ``role`` identifier, ascending, so pages are stable.

    Args:
        roles (list[dict]): Role catalog entries, with ``user_count`` and ``updated_at`` set.
        sort_by (RoleSortField, optional): The field to sort by. Defaults to ``display_name``.
        order (SortOrder, optional): The order to sort by. Defaults to ``asc``.

    Raises:
        ValueError: If the sort field is invalid.
        ValueError: If the sort order is invalid.

    Returns:
        list[dict]: The sorted roles.
    """
    if sort_by not in RoleSortField.values():
        raise ValueError(f"Invalid field: '{sort_by}'. Must be one of {RoleSortField.values()}")
    if order not in SortOrder.values():
        raise ValueError(f"Invalid order: '{order}'. Must be one of {SortOrder.values()}")

    # Sort by identifier first: the sort below is stable, also when reversed, so this breaks ties.
    by_role = sorted(roles, key=lambda role: role["role"])
    with_value = [role for role in by_role if _role_sort_value(role, sort_by) is not None]
    without_value = [role for role in by_role if _role_sort_value(role, sort_by) is None]
    with_value.sort(key=lambda role: _role_sort_value(role, sort_by), reverse=order == SortOrder.DESC)
    return with_value + without_value


def inject_scope_display_names(assignments: list[SerializedAssignment]) -> None:
    """Set ``scope_display_name`` in-place on serialized assignments using one bulk lookup.

    Callers must pass only the assignments of the current page, after filtering,
    sorting and pagination. This avoids DB lookups for assignments that are not
    in the response and keeps the cost at one batched query per scope type
    (libraries and courses) instead of one per assignment. Unresolvable scopes
    (globs, superadmin entries, missing resources) get an empty string.

    Args:
        assignments: Serialized assignments for the current page. Each one
            must have a ``scope`` key. They are modified in-place, and
            ``scope_display_name`` is set on every entry.
    """
    scope_keys = {a["scope"] for a in assignments if a.get("scope")}
    display_name_map = get_scope_display_name_map(scope_keys)
    for assignment in assignments:
        assignment["scope_display_name"] = display_name_map.get(assignment.get("scope", ""), "")
