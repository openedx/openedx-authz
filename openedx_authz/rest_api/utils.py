"""Utility functions for the Open edX AuthZ REST API."""

from openedx_authz import api
from openedx_authz.api.data import (
    GLOBAL_SCOPE_WILDCARD,
    ScopeData,
)
from openedx_authz.api.users import get_scopes_for_user_and_permission
from openedx_authz.rest_api.data import (
    AssignmentSortField,
    BaseEnum,
    SearchField,
    SortField,
    SortOrder,
    UserAssignmentSortField,
)

try:
    # common.djangoapps.student.roles and openedx.core are edx-platform's own modules. This app
    # is an edx-platform plugin, so they're always available at runtime; the imports are only
    # guarded so this module can still load under this repo's own standalone test suite
    # (openedx_authz.settings.test, no edx-platform installed).
    from common.djangoapps.student.roles import enable_authz_course_authoring
    from openedx.core.djangoapps.waffle_utils.models import WaffleFlagOrgOverrideModel
    from openedx.core.toggles import AUTHZ_COURSE_AUTHORING_FLAG
except ImportError:
    enable_authz_course_authoring = None
    WaffleFlagOrgOverrideModel = None
    AUTHZ_COURSE_AUTHORING_FLAG = None


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


def is_scope_visible(scope: api.ScopeData) -> bool:
    """Return whether a scope is visible under the course-authoring flag.

    See ``docs/decisions/0015-course-authoring-flag-visibility-in-rest-api.rst``
    for the reasoning: Casbin data cannot be trusted as a proxy for
    ``authz.enable_course_authoring``'s effective state, since the migration
    that is supposed to keep Casbin in sync with the flag is opt-in, off by
    default, and never runs for platform-wide flag changes. Only the flag
    itself, checked directly, can answer whether a scope is visible.

    - Library and other non-course scopes (e.g. 'lib:DemoX:CSPROB'): always visible.
    - Concrete course (e.g. 'course-v1:DemoX+CS101+2024'): full course/org/platform
      cascade via ``enable_authz_course_authoring(course_key)``.
    - Org-level course glob (e.g. 'course-v1:DemoX+*'): org override, else platform default.
    - Platform-level course glob ('course-v1:*'): platform tier only, no course or org.

    Args:
        scope (ScopeData): A resolved scope instance.

    Returns:
        bool: True if the scope should count as visible.
    """
    if scope.NAMESPACE != api.CourseOverviewData.NAMESPACE:
        return True
    if isinstance(scope, api.CourseOverviewData):
        return enable_authz_course_authoring(scope.course_key)
    if isinstance(scope, api.OrgCourseOverviewGlobData):
        # enable_authz_course_authoring only accepts a course key, and there's no public
        # edx-platform API to check an org alone, so this checks the org override directly
        # (see issue #360 for follow-up) when asked to check an org-level course glob
        org_override = WaffleFlagOrgOverrideModel.override_value(AUTHZ_COURSE_AUTHORING_FLAG.name, scope.org)
        if org_override == WaffleFlagOrgOverrideModel.ALL_CHOICES.on:
            return True
        if org_override == WaffleFlagOrgOverrideModel.ALL_CHOICES.off:
            return False
    return enable_authz_course_authoring()


def has_visible_scope(username: str, action: str, scope_value: str | None) -> bool:
    """Return whether the user has a course-authoring-visible scope for this action.

    Args:
        username (str): The user checking the action.
        action (str): The action being validated.
        scope_value (str | None): The external key of the scope being
            validated, or None to check across any scope the user has the
            action in.

    Returns:
        bool: True if the user has a visible scope for this action, False otherwise.
    """
    if scope_value:
        return is_scope_visible(api.ScopeData(external_key=scope_value))
    return any(is_scope_visible(scope) for scope in get_scopes_for_user_and_permission(username, action))
