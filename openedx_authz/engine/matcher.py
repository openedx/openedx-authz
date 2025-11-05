"""Custom condition checker. Note only used for data_library scope"""

from django.contrib.auth import get_user_model

from openedx_authz.api.data import ContentLibraryData, ScopeData, UserData
from openedx_authz.rest_api.utils import get_user_by_username_or_email

User = get_user_model()


def is_admin_or_superuser_check(request_user: str, request_action: str, request_scope: str) -> bool:  # pylint: disable=unused-argument
    """
    Evaluates custom, non-role-based conditions for authorization checks.

    Checks attribute-based conditions that don't rely on role assignments.
    Currently handles ContentLibraryData scopes by granting access to staff
    and superusers.

    Args:
        request_user (str): Namespaced user key (format: "user::<username>")
        request_action (str): Namespaced action key (format: "action::<action_name>")
        request_scope (str): Namespaced scope key (format: "scope_type::<scope_id>")

    Returns:
        bool: True if the condition is satisfied (user is staff/superuser for
              ContentLibraryData scopes), False otherwise (including when user
              doesn't exist or scope type is not supported)
    """
    try:
        username = UserData(namespaced_key=request_user).external_key
        user = get_user_by_username_or_email(username)
    except User.DoesNotExist:
        return False

    scope = ScopeData(namespaced_key=request_scope)

    if isinstance(scope, ContentLibraryData):
        return user.is_staff or user.is_superuser

    return False
