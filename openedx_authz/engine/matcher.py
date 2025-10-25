"""Custom condition checker. Note only used for data_library scope"""

from django.conf import settings
from django.contrib.auth import get_user_model

from openedx_authz.api.data import ActionData, ContentLibraryData, ScopeData, UserData
from openedx_authz.rest_api.utils import get_user_by_username_or_email

User = get_user_model()


def is_course_creator(user) -> bool:
    """
    Checks if a user is a course creator.
    """
    # pylint: disable=import-outside-toplevel
    try:
        from cms.djangoapps.course_creators.views import get_course_creator_status
    except ImportError:
        get_course_creator_status = None

    return get_course_creator_status(user) == "granted"


def is_studio_request() -> bool:
    """
    Checks if the request is a studio request.
    """
    return settings.SERVICE_VARIANT == "cms"


def check_custom_conditions(request_user: str, request_action: str, request_scope: str) -> bool:
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

    scope = ScopeData(namespaced_key=request_scope)
    scope_obj = scope.get_object()

    if scope_obj is None:
        return False

    if user.is_staff or user.is_superuser:
        return True

    action = ActionData(namespaced_key=request_action)

    if isinstance(scope, ContentLibraryData):
        if is_studio_request():
            if action.external_key == "create_library":
                return is_course_creator(user)
            if action.external_key == "view_library":
                return scope_obj.allow_public_read and is_course_creator(user)

    return False
