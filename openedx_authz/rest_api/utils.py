"""Utility functions for the Open edX AuthZ REST API."""

from django.contrib.auth import get_user_model
from django.db.models import Q
from edx_rest_framework_extensions.auth.jwt.authentication import JwtAuthentication
from edx_rest_framework_extensions.auth.session.authentication import SessionAuthenticationAllowInactiveUser

User = get_user_model()


def view_auth_classes(func_or_class):
    """
    Function and class decorator that abstracts the authentication classes for api views.
    """

    def _decorator(func_or_class):
        """
        Requires either OAuth2 or Session-based authentication;
        are the same authentication classes used on edx-platform
        """
        func_or_class.authentication_classes = (
            JwtAuthentication,
            SessionAuthenticationAllowInactiveUser,
        )
        return func_or_class

    return _decorator(func_or_class)


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
