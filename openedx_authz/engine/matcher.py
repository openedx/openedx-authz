"""Custom condition checker. Note only used for data_library scope"""

from django.contrib.auth import get_user_model
from django.core.cache import cache

from openedx_authz.api.data import ContentLibraryData, ScopeData, UserData
from openedx_authz.rest_api.utils import get_user_by_username_or_email

RBAC_ADMIN_CACHE_KEY_FMT = "rbac_is_admin_or_superuser_{username}"
RBAC_ADMIN_CACHE_TIMEOUT_SECS = 2

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

    scope = ScopeData(namespaced_key=request_scope)
    username = UserData(namespaced_key=request_user).external_key

    # TODO: This special case for superuser and staff users is currently only for
    # content libraries. See: https://github.com/openedx/openedx-authz/issues/87
    if not isinstance(scope, ContentLibraryData):
        return False

    cache_key = RBAC_ADMIN_CACHE_KEY_FMT.format(username=username)
    is_allowed = cache.get(cache_key)

    if is_allowed is not None:
        return is_allowed

    try:
        user = get_user_by_username_or_email(username)
    except User.DoesNotExist:
        return False

    is_allowed = user.is_staff or user.is_superuser

    # TODO: Make this cache timeout configurable
    cache.set(cache_key, is_allowed, RBAC_ADMIN_CACHE_TIMEOUT_SECS)

    return is_allowed
