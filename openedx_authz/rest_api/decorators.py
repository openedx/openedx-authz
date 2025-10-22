"""Decorators for the Open edX AuthZ REST API."""

from functools import wraps

from edx_rest_framework_extensions.auth.jwt.authentication import JwtAuthentication
from edx_rest_framework_extensions.auth.session.authentication import SessionAuthenticationAllowInactiveUser
from rest_framework.permissions import IsAuthenticated


def view_auth_classes(is_authenticated=True):
    """
    Function and class decorator that abstracts the authentication and permission checks for api views.

    Args:
        is_authenticated: Whether the view requires authentication.

    Returns:
        The decorated view or class.

    Examples:
        >>> @view_auth_classes(is_authenticated=False)
        ... class MyView(APIView):
        ...     def get(self, request):
        ...         return Response("Hello, world!")
    """

    def _decorator(func_or_class):
        """
        Requires either OAuth2 or Session-based authentication.

        Args:
            func_or_class: The view or class to decorate.

        Returns:
            The decorated view or class.
        """
        func_or_class.authentication_classes = [
            JwtAuthentication,
            SessionAuthenticationAllowInactiveUser,
        ]
        if is_authenticated:
            func_or_class.permission_classes = [IsAuthenticated] + getattr(func_or_class, "permission_classes", [])
        return func_or_class

    return _decorator


def authz_permissions(permissions: list[str]):
    """Decorator to attach required permissions to view methods.

    This decorator stores a list of permission identifiers that will be checked
    by MethodPermissionMixin during authorization.

    Args:
        permissions: List of permission identifiers (e.g., ["view_library_team", "manage_library_team"])

    Examples:
        >>> class MyView(APIView):
        ...     @authz_permissions(["view_library_team"])
        ...     def get(self, request):
        ...         pass
        ...
        ...     @authz_permissions(["manage_library_team"])
        ...     def post(self, request):
        ...         pass
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        wrapper.required_permissions = permissions
        return wrapper

    return decorator
