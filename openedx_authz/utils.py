"""General utility functions for Open edX AuthZ."""

from django.contrib.auth import get_user_model
from django.db.models import Q

User = get_user_model()


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
