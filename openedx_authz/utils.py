"""General utility functions for Open edX AuthZ."""

from django.contrib.auth import get_user_model
from django.db.models import Q
from edx_django_utils.cache import RequestCache

User = get_user_model()

_STAFF_SUPERUSER_CACHE_NAMESPACE = "rbac_is_staff_or_superuser"


def is_user_staff_or_superuser(username: str) -> bool:
    """
    Return True if the user with the given username is staff or superuser.

    Uses RequestCache to avoid repeated DB lookups within the same request.
    Returns False if the user does not exist or is inactive.
    """
    cache = RequestCache(_STAFF_SUPERUSER_CACHE_NAMESPACE)
    cached = cache.get_cached_response(username)
    if cached.is_found:
        return cached.value
    try:
        user = User.objects.get(username=username, is_active=True)
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
