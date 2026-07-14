"""General utility functions for Open edX AuthZ."""

from django.contrib.auth import get_user_model
from django.db.models import Q
from edx_django_utils.cache import RequestCache

try:
    from openedx.core.djangoapps.waffle_utils.models import (
        WaffleFlagCourseOverrideModel,
        WaffleFlagOrgOverrideModel,
    )
    from openedx.core.toggles import AUTHZ_COURSE_AUTHORING_FLAG
except ImportError:
    WaffleFlagCourseOverrideModel = None
    WaffleFlagOrgOverrideModel = None
    AUTHZ_COURSE_AUTHORING_FLAG = None

from waffle.models import Flag

# Match handlers.py semantics: an override forces ON when override_choice == "on"
WAFFLE_OVERRIDE_FORCE_ON = "on"
WAFFLE_OVERRIDE_FORCE_OFF = "off"

User = get_user_model()

_STAFF_SUPERUSER_CACHE_NAMESPACE = "rbac_is_staff_or_superuser"


def is_user_staff_or_superuser(username: str) -> bool:
    """
    Return True if the user with the given username is staff or superuser.

    Uses RequestCache to avoid repeated DB lookups within the same request.
    Returns False if the user does not exist or has a retirement request.
    """
    cache = RequestCache(_STAFF_SUPERUSER_CACHE_NAMESPACE)
    cached = cache.get_cached_response(username)
    if cached.is_found:
        return cached.value

    try:
        user = get_user_by_username_or_email(username)
    except User.DoesNotExist:
        return False

    result = user.is_staff or user.is_superuser
    cache.set(username, result)

    return result


def get_user_by_username_or_email(username_or_email: str) -> User:
    """
    Retrieve a user by their username or email address.

    Args:
        username_or_email (str): The username or email address to search for.

    Returns:
        User: The User object if found and not retired.

    Raises:
        User.DoesNotExist: If no user matches the provided username or email,
            or if the user has an associated retirement request.
    """
    user = User.objects.get(Q(email=username_or_email) | Q(username=username_or_email))
    if hasattr(user, "userretirementrequest"):
        raise User.DoesNotExist
    return user


def get_waffle_flag_states() -> dict:
    """
    Retrieve the enablement state of the course-authoring waffle flag across different scopes.

    Returns:
        dict: A dictionary mapping scopes to their activation status:
            * 'global' (bool): True if the global waffle flag is enabled for everyone.
            * 'org_overrides' (dict): Orgs with an organization-level override, as 'on'
              (forces the flag on) and 'off' (forces the flag off) lists.
            * 'course_overrides' (dict): Courses with a course-level override, split the same way.
    """
    # Global flag (falls back False if toggle not available)
    global_enabled = False
    if AUTHZ_COURSE_AUTHORING_FLAG is not None:
        gf = Flag.objects.filter(name=AUTHZ_COURSE_AUTHORING_FLAG.name).first()
        global_enabled = bool(gf and gf.everyone)

    # There's no public edx-platform API to get which orgs/courses have an override, only
    # override_value(name, key) for one specific org/course at a time, so this queries the
    # model directly. This is a temporary solution which should be addressed by
    # https://github.com/openedx/openedx-authz/issues/360
    org_override_rows = list(
        WaffleFlagOrgOverrideModel.objects.current_set()
        .filter(waffle_flag=AUTHZ_COURSE_AUTHORING_FLAG.name, enabled=True)
        .values_list("org", "override_choice")
    )
    course_override_rows = list(
        WaffleFlagCourseOverrideModel.objects.current_set()
        .filter(waffle_flag=AUTHZ_COURSE_AUTHORING_FLAG.name, enabled=True)
        .values_list("course_id", "override_choice")
    )

    return {
        "global": global_enabled,
        "org_overrides": {
            "on": [org for org, choice in org_override_rows if choice == WAFFLE_OVERRIDE_FORCE_ON],
            "off": [org for org, choice in org_override_rows if choice == WAFFLE_OVERRIDE_FORCE_OFF],
        },
        "course_overrides": {
            "on": [
                str(course_id) for course_id, choice in course_override_rows if choice == WAFFLE_OVERRIDE_FORCE_ON
            ],
            "off": [
                str(course_id) for course_id, choice in course_override_rows if choice == WAFFLE_OVERRIDE_FORCE_OFF
            ],
        },
    }
