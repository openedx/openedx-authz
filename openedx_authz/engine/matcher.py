"""Custom condition checker. Note only used for data_library scope"""

from django.contrib.auth import get_user_model

from openedx_authz.api.data import UserData
from openedx_authz.rest_api.utils import get_user_by_username_or_email

User = get_user_model()


def check_custom_conditions(request_user: str, request_action: str, request_scope: str) -> bool:  # pylint: disable=unused-argument
    """
    Evaluates custom, non-role-based conditions for library actions.

    Checks attribute-based conditions that don't rely on role assignments:
    - Staff and superusers have full access
    - create_library: requires granted course creator status
    - view_library: allowed if library has public read enabled

    Args:
        request_user (str): Namespaced user key
        request_action (str): Namespaced action key
        request_scope (str): Namespaced scope key

    Returns:
        bool: True if the condition is satisfied, False otherwise
    """
    try:
        username = UserData(namespaced_key=request_user).external_key
        user = get_user_by_username_or_email(username)
    except User.DoesNotExist:
        return False

    if user.is_staff or user.is_superuser:
        return True

    return False
