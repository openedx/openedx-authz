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
    """Check non-role-based authorization conditions for supported scope types.

    Grants access to staff and superusers for ContentLibraryData and CourseOverviewData
    scopes. Returns False for all other scope types.

    Args:
        request_user: Namespaced user key (format: "user^<username>").
        request_action: Namespaced action key (format: "action^<action_name>").
        request_scope: Namespaced scope key (format: "scope_type^<scope_id>").

    Returns:
        True if the user is staff or superuser and the scope type is supported.
    """
    scope = ScopeData(namespaced_key=request_scope)

    # TODO: This special case is currently only for content libraries and course overviews.
    # See: https://github.com/openedx/openedx-authz/issues/87
    if (scope.NAMESPACE, type(scope)) not in SCOPES_WITH_ADMIN_OR_SUPERUSER_CHECK:
        return False
    username = UserData(namespaced_key=request_user).external_key
    return is_user_staff_or_superuser(username)
