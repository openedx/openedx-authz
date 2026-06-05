"""Custom condition checker. Note only used for data_library scope"""

from openedx_authz.api.data import (
    ContentLibraryData,
    CourseOverviewData,
    OrgContentLibraryGlobData,
    OrgCourseOverviewGlobData,
    PlatformCourseOverviewGlobData,
    ScopeData,
    UserData,
)
from openedx_authz.utils import is_user_staff_or_superuser

SCOPES_WITH_ADMIN_OR_SUPERUSER_CHECK = {
    (ContentLibraryData.NAMESPACE, ContentLibraryData),
    (CourseOverviewData.NAMESPACE, CourseOverviewData),
    (OrgContentLibraryGlobData.NAMESPACE, OrgContentLibraryGlobData),
    (OrgCourseOverviewGlobData.NAMESPACE, OrgCourseOverviewGlobData),
    (PlatformCourseOverviewGlobData.NAMESPACE, PlatformCourseOverviewGlobData),
}


def is_admin_or_superuser_check(request_user: str, request_action: str, request_scope: str) -> bool:  # pylint: disable=unused-argument
    """
    Evaluates custom, non-role-based conditions for authorization checks.

    Checks attribute-based conditions that don't rely on role assignments.
    Currently handles ContentLibraryData and CourseOverviewData scopes by granting access to staff
    and superusers.

    Args:
        request_user (str): Namespaced user key (format: "user::<username>")
        request_action (str): Namespaced action key (format: "action::<action_name>")
        request_scope (str): Namespaced scope key (format: "scope_type::<scope_id>")

    Returns:
        bool: True if the condition is satisfied (user is staff/superuser for
              ContentLibraryData and CourseOverviewData scopes), False otherwise (including when user
              doesn't exist or scope type is not supported)
    """

    scope = ScopeData(namespaced_key=request_scope)
    username = UserData(namespaced_key=request_user).external_key

    # TODO: This special case for superuser and staff users is currently only for
    # content libraries and course overviews. See: https://github.com/openedx/openedx-authz/issues/87
    if (scope.NAMESPACE, type(scope)) not in SCOPES_WITH_ADMIN_OR_SUPERUSER_CHECK:
        return False

    return is_user_staff_or_superuser(username)
