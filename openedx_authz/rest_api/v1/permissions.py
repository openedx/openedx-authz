"""Permissions for the Open edX AuthZ REST API."""

from typing import ClassVar

from rest_framework.permissions import BasePermission

from openedx_authz import api


class PermissionMeta(type(BasePermission)):
    """Metaclass that automatically registers permission classes by namespace.

    This metaclass maintains a registry of permission classes indexed by their NAMESPACE
    attribute. When a permission class is defined with a NAMESPACE, it is automatically
    registered in the permission_registry for later retrieval.
    """

    permission_registry: dict[str, type["BaseScopePermission"]] = {}

    def __init__(cls, name, bases, attrs):
        """Initialize the metaclass and register subclasses."""
        super().__init__(name, bases, attrs)
        namespace = getattr(cls, "NAMESPACE", None)
        if namespace:
            cls.permission_registry[namespace] = cls

    @classmethod
    def get_permission_class(mcs, namespace: str) -> type["BaseScopePermission"]:
        """Retrieve the permission class for the given namespace.

        Args:
            namespace: The namespace identifier (e.g., 'lib', 'sc').

        Returns:
            type["BaseScopePermission"]: The permission class for the namespace,
                or BaseScopePermission if the namespace is not registered.

        Examples:
            >>> PermissionMeta.get_permission_class("lib")
            <class 'ContentLibraryPermission'>
            >>> PermissionMeta.get_permission_class("unknown")
            <class 'BaseScopePermission'>
        """
        return mcs.permission_registry.get(namespace, BaseScopePermission)


class BaseScopePermission(BasePermission, metaclass=PermissionMeta):
    """Base permission class for all scope-based permissions.

    This class provides the foundation for implementing scope-based authorization checks
    in the REST API. It extracts scope information from requests and provides hooks for
    permission validation. Subclasses should override the permission methods to implement
    specific authorization logic for their scope types.
    """

    NAMESPACE: ClassVar[str] = "sc"
    """The namespace identifier for this permission class. Default ``sc`` for generic scopes."""

    def get_scope_value(self, request) -> str | None:
        """Extract the scope value from the request.

        Args:
            request: The Django REST framework request object.

        Returns:
            str | None: The scope value if found (e.g., 'lib:DemoX:CSPROB'), or None if not present.
        """
        return request.data.get("scope") or request.query_params.get("scope")

    def get_scope_namespace(self, request) -> str:
        """Derive the namespace from the request scope value.

        Attempts to parse the scope value and extract its namespace. If the scope value
        is invalid or missing, falls back to this class's NAMESPACE.

        Args:
            request: The Django REST framework request object.

        Returns:
            str: The scope namespace (e.g., 'lib', 'sc').

        Examples:
            >>> request.data = {"scope": "lib:DemoX:CSPROB"}
            >>> permission.get_scope_namespace(request)
            'lib'
            >>> request.data = {}
            >>> permission.get_scope_namespace(request)
            'sc'
        """
        scope_value = self.get_scope_value(request)
        if not scope_value:
            return self.NAMESPACE
        try:
            return api.ScopeData(external_key=scope_value).NAMESPACE
        except ValueError:
            return self.NAMESPACE

    def has_permission(self, request, view) -> bool:
        """Fallback permission check (deny by default).

        Subclasses should override this method to implement their specific permission logic.

        Returns:
            bool: False (deny access by default).
        """
        return False

    def has_object_permission(self, request, view, obj) -> bool:
        """Fallback object-level permission check (deny by default).

        Subclasses should override this method to implement their specific object-level
        permission logic.

        Returns:
            bool: False (deny access by default).
        """
        return False


class DynamicScopePermission(BaseScopePermission):
    """Dispatcher permission class that delegates permission checks to scope-specific handlers.

    This class acts as a dispatcher that automatically selects and delegates to the appropriate
    permission class based on the request's scope namespace. It also provides special handling
    for superusers and staff members.

    Permission Flow:
        1. Check if user is superuser or staff (automatic approval).
        2. Extract the scope namespace from the request.
        3. Look up the appropriate permission class for that namespace.
        4. Delegate the permission check to that class.

    Examples:
        >>> permission = ScopePermission()
        >>> # For a library scope request, this will delegate to ContentLibraryPermission
        >>> request.data = {"scope": "lib:DemoX:CSPROB"}
        >>> ContentLibraryPermission.has_permission(request, view)
        >>> # For a generic scope request, this will delegate to BaseScopePermission
        >>> request.data = {"scope": "sc:generic"}
        >>> BaseScopePermission.has_permission(request, view)

    Note:
        Superusers and staff members always have permission regardless of scope.
    """

    NAMESPACE: ClassVar[None] = None
    """This is a dispatcher, not tied to a specific namespace."""

    def _get_permission_instance(self, request) -> BaseScopePermission:
        """Instantiate the permission class for the request scope.

        Determines the appropriate permission class based on the scope namespace
        extracted from the request and returns an instance of that class.

        Args:
            request: The Django REST framework request object.

        Returns:
            BaseScopePermission: An instance of the permission class appropriate
                for the request's scope namespace.

        Examples:
            >>> request.data = {"scope": "lib:DemoX:CSPROB"}
            >>> permission._get_permission_instance(request)
            >>> ContentLibraryPermission
        """
        scope_namespace = self.get_scope_namespace(request)
        perm_class = PermissionMeta.get_permission_class(scope_namespace)
        return perm_class()

    def has_permission(self, request, view) -> bool:
        """Delegate permission check to the appropriate scope-specific permission class.

        Superusers and staff members are automatically granted permission. For other
        users, the permission check is delegated to the permission class registered
        for the request's scope namespace.

        Examples:
            >>> # Regular user gets scope-specific check
            >>> request.data = {"scope": "lib:DemoX:CSPROB"}
            >>> permission.has_permission(request, view)  # Delegates to ContentLibraryPermission
        """
        if request.user.is_superuser or request.user.is_staff:
            return True
        return self._get_permission_instance(request).has_permission(request, view)

    def has_object_permission(self, request, view, obj) -> bool:
        """Delegate object-level permission check to the appropriate scope-specific permission class.

        Superusers and staff members are automatically granted permission. For other
        users, the object-level permission check is delegated to the permission class
        registered for the request's scope namespace.

        Examples:
            >>> # Regular user gets scope-specific check
            >>> request.data = {"scope": "lib:DemoX:CSPROB"}
            >>> permission.has_object_permission(request, view, obj)  # Delegates to ContentLibraryPermission
        """
        if request.user.is_superuser or request.user.is_staff:
            return True
        return self._get_permission_instance(request).has_object_permission(request, view, obj)


class MethodPermissionMixin:
    """Mixin that validates permissions defined via @authz_permissions decorator.

    This mixin reads the required_permissions attribute set by the @authz_permissions
    decorator and validates each permission using ``is_user_allowed``. All permissions
    must be satisfied for the check to pass.

    Usage:
        Combine this mixin with BaseScopePermission to create permission classes
        that use method-level permission declarations:

        >>> class MyPermission(MethodPermissionMixin, BaseScopePermission):
        ...     NAMESPACE = "lib"
        ...
        >>> class MyView(APIView):
        ...     permission_classes = [MyPermission]
        ...
        ...     @authz_permissions(["view_library_team"])
        ...     def get(self, request):
        ...         pass
    """

    def get_required_permissions(self, request, view) -> list[str]:
        """Extract required permissions from the view method.

        Args:
            request: The Django REST framework request object.
            view: The view being accessed.

        Returns:
            list[str]: List of permission identifiers, or empty list if not defined.
        """
        method = request.method.lower()
        handler = getattr(view, method, None)
        if handler and hasattr(handler, "required_permissions"):
            return handler.required_permissions
        return []

    def validate_permissions(self, request, permissions: list[str], scope_value: str) -> bool:
        """Validate that the user has all required permissions for the scope.

        Args:
            request: The Django REST framework request object.
            permissions: List of permission identifiers to check.
            scope_value: The scope to check permissions against.

        Returns:
            bool: True if user has all required permissions, False otherwise.
        """
        if not permissions:
            return False

        for permission in permissions:
            if not api.is_user_allowed(request.user.username, permission, scope_value):
                return False
        return True


class ContentLibraryPermission(MethodPermissionMixin, BaseScopePermission):
    """Permission handler for content library scopes.

    This class implements permission checks specific to content library operations.
    It uses the authz API to verify whether a user has the necessary permissions
    to perform actions on library team members.
    """

    NAMESPACE: ClassVar[str] = "lib"
    """``lib`` for content library scopes."""

    def has_permission(self, request, view) -> bool:
        """Check if the user has permission to perform the requested action.

        First checks if the view method has @authz_permissions decorator.
        If present, validates all required permissions. If not present,
        allows access by default.

        Returns:
            bool: True if the user has the required permission, False otherwise.
                Also returns False if no scope value is provided in the request.
        """
        scope_value = self.get_scope_value(request)
        if not scope_value:
            return False

        permissions = self.get_required_permissions(request, view)
        if permissions:
            return self.validate_permissions(request, permissions, scope_value)

        return True
