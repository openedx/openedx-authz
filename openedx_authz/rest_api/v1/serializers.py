"""Serializers for the Open edX AuthZ REST API."""

from django.contrib.auth import get_user_model
from rest_framework import serializers

from openedx_authz import api
from openedx_authz.rest_api.data import SortField, SortOrder
from openedx_authz.rest_api.v1.fields import CommaSeparatedListField, LowercaseCharField

User = get_user_model()


class ScopeMixin(serializers.Serializer):  # pylint: disable=abstract-method
    """Mixin providing scope field functionality."""

    scope = serializers.CharField(max_length=255)


class RoleMixin(serializers.Serializer):  # pylint: disable=abstract-method
    """Mixin providing role field functionality."""

    role = serializers.CharField(max_length=255)


class ActionMixin(serializers.Serializer):  # pylint: disable=abstract-method
    """Mixin providing action field functionality."""

    action = serializers.CharField(max_length=255)


class PermissionValidationSerializer(ActionMixin, ScopeMixin):  # pylint: disable=abstract-method
    """Serializer for permission validation request."""


class PermissionValidationResponseSerializer(PermissionValidationSerializer):  # pylint: disable=abstract-method
    """Serializer for permission validation response."""

    allowed = serializers.BooleanField()


class RoleScopeValidationMixin(serializers.Serializer):  # pylint: disable=abstract-method
    """Mixin providing role and scope validation logic."""

    def validate(self, attrs):
        """Validate that role exists in scope."""
        validated_data = super().validate(attrs)
        scope_value = validated_data["scope"]
        role_value = validated_data["role"]

        try:
            scope = api.ScopeData(external_key=scope_value)
        except ValueError as exc:
            raise serializers.ValidationError(exc) from exc

        if not scope.exists():
            raise serializers.ValidationError(f"Scope '{scope_value}' does not exist")

        role = api.RoleData(external_key=role_value)
        general_scope = api.ScopeData(namespaced_key=f"{scope.NAMESPACE}{scope.SEPARATOR}*")
        role_definitions = api.get_role_definitions_in_scope(general_scope)

        if role not in role_definitions:
            raise serializers.ValidationError(f"Role '{role_value}' does not exist in scope '{scope_value}'")

        return validated_data


class AddUsersToRoleWithScopeSerializer(
    RoleScopeValidationMixin,
    RoleMixin,
    ScopeMixin,
):  # pylint: disable=abstract-method
    """Serializer for adding users to a role with a scope."""

    users = serializers.ListField(child=serializers.CharField(max_length=255), allow_empty=False)


class RemoveUsersFromRoleWithScopeSerializer(
    RoleScopeValidationMixin,
    RoleMixin,
    ScopeMixin,
):  # pylint: disable=abstract-method
    """Serializer for removing users from a role with a scope."""

    users = CommaSeparatedListField(allow_blank=False)


class ListUsersInRoleWithScopeSerializer(ScopeMixin):  # pylint: disable=abstract-method
    """Serializer for listing users in a role with a scope."""

    roles = CommaSeparatedListField(required=False, default=[])
    sort_by = serializers.ChoiceField(
        required=False, choices=[(e.value, e.name) for e in SortField], default=SortField.USERNAME
    )
    order = serializers.ChoiceField(
        required=False, choices=[(e.value, e.name) for e in SortOrder], default=SortOrder.ASC
    )
    search = LowercaseCharField(required=False, default=None)


class ListRolesWithNamespaceSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """Serializer for listing roles within a namespace."""

    namespace = serializers.CharField(max_length=255)

    def validate_namespace(self, value: str) -> api.ScopeData:
        """Validate and convert namespace string to a ScopeData instance.

        Checks that the provided namespace is registered in the scope registry and
        returns an instance of the appropriate ScopeData subclass with a wildcard
        external_key to represent all scopes within that namespace.

        Args:
            value: The namespace string to validate (e.g., 'lib', 'sc', 'org').

        Returns:
            ScopeData: An instance of the appropriate ScopeData subclass for the
                namespace, initialized with external_key="*".

        Raises:
            serializers.ValidationError: If the namespace is not registered in the scope registry.

        Examples:
            >>> validate_namespace('lib')
            ContentLibraryData(external_key='*')
        """
        namespaces = api.ScopeData.get_all_namespaces()
        if value not in namespaces:
            raise serializers.ValidationError(f"'{value}' is not a valid namespace")
        return namespaces[value](external_key="*")


class ListUsersInRoleWithScopeResponseSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """Serializer for listing users in a role with a scope response."""

    username = serializers.CharField(max_length=255)
    full_name = serializers.CharField(max_length=255)
    email = serializers.EmailField()


class ListRolesWithScopeResponseSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """Serializer for listing roles with a scope response."""

    role = serializers.CharField(max_length=255)
    permissions = serializers.ListField(child=serializers.CharField(max_length=255))
    user_count = serializers.IntegerField()


class UserRoleAssignmentSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """Serializer for a user role assignment."""

    username = serializers.SerializerMethodField()
    full_name = serializers.SerializerMethodField()
    email = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._user_cache = {}

    def _get_user(self, obj) -> User | None:
        """Get the user object for the given role assignment."""
        user_map = self.context.get("user_map", {})
        return user_map.get(obj.subject.username)

    def get_username(self, obj: api.RoleAssignmentData) -> str:
        """Get the username for the given role assignment."""
        return obj.subject.username

    def get_full_name(self, obj) -> str:
        """Get the full name for the given role assignment."""
        user = self._get_user(obj)
        return getattr(user.profile, "name", "") if user and hasattr(user, "profile") else ""

    def get_email(self, obj) -> str:
        """Get the email for the given role assignment."""
        user = self._get_user(obj)
        return getattr(user, "email", "") if user else ""

    def get_roles(self, obj: api.RoleAssignmentData) -> list[str]:
        """Get the roles for the given role assignment."""
        return [role.external_key for role in obj.roles]
