"""Serializers for the Open edX AuthZ REST API."""

from django.contrib.auth import get_user_model
from rest_framework import serializers

from openedx_authz import api
from openedx_authz.rest_api.data import SortField, SortOrder
from openedx_authz.rest_api.utils import get_generic_scope
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

    def validate(self, attrs) -> dict:
        """Validate that the specified role and scope are valid and that the role exists in the scope.

        This method performs the following validations:
        1. Validates that the scope is registered in the scope registry
        2. Validates that the scope exists in the system
        3. Validates that the role is defined into the roles assigned to the scope

        Args:
            attrs: Dictionary containing 'role' and 'scope' keys with their string values.

        Returns:
            dict: The validated data dictionary with 'role' and 'scope' keys.

        Raises:
            serializers.ValidationError: If the scope is not registered, doesn't exist,
                or if the role is not defined in the scope.
        """
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
        generic_scope = get_generic_scope(scope)
        role_definitions = api.get_role_definitions_in_scope(generic_scope)

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

    def validate_users(self, value) -> list[str]:
        """Eliminate duplicates preserving order"""
        return list(dict.fromkeys(value))


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


class ListRolesWithScopeSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """Serializer for listing roles within a scope."""

    scope = serializers.CharField(max_length=255)

    def validate_scope(self, value: str) -> api.ScopeData:
        """Validate and convert scope string to a ScopeData instance.

        Checks that the provided scope is registered in the scope registry and
        returns an instance of the appropriate ScopeData subclass.

        Args:
            value: The scope string to validate (e.g., 'lib', 'sc', 'org').

        Returns:
            ScopeData: An instance of the appropriate ScopeData subclass for the scope.

        Raises:
            serializers.ValidationError: If the scope is not registered in the scope registry.

        Examples:
            >>> validate_scope('lib:DemoX:CSPROB')
            ContentLibraryData(external_key='lib:DemoX:CSPROB')
        """
        try:
            return api.ScopeData(external_key=value)
        except ValueError as exc:
            raise serializers.ValidationError(exc) from exc


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
