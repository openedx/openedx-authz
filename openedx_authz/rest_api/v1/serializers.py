"""Serializers for the Open edX AuthZ REST API."""

from rest_framework import serializers


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


class AddUserToRoleWithScopeSerializer(RoleMixin, ScopeMixin):  # pylint: disable=abstract-method
    """Serializer for adding a user to a role with a scope."""

    users = serializers.ListField(child=serializers.CharField(max_length=255))


class RemoveUserFromRoleWithScopeSerializer(RoleMixin, ScopeMixin):  # pylint: disable=abstract-method
    """Serializer for removing a user from a role with a scope."""

    user = serializers.CharField(max_length=255)


class ListUsersInRoleWithScopeSerializer(ScopeMixin):  # pylint: disable=abstract-method
    """Serializer for listing users in a role with a scope."""

    role = serializers.CharField(max_length=255, required=False)


class ListRolesWithScopeSerializer(ScopeMixin):  # pylint: disable=abstract-method
    """Serializer for listing roles with a scope."""


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
