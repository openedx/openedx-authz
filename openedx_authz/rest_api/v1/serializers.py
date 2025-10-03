"""Serializers for the Open edX AuthZ REST API."""

from rest_framework import serializers

from openedx_authz.rest_api.utils import get_user_by_username_or_email
from openedx_authz.rest_api.v1.fields import CommaSeparatedListField

__all__ = [
    "PermissionValidationSerializer",
    "PermissionValidationResponseSerializer",
    "AddUserToRoleWithScopeSerializer",
    "RemoveUserFromRoleWithScopeSerializer",
    "ListUsersInRoleWithScopeSerializer",
    "ListRolesWithScopeSerializer",
    "ListUsersInRoleWithScopeResponseSerializer",
    "ListRolesWithScopeResponseSerializer",
    "RoleAssignmentSerializer",
]


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

    users = CommaSeparatedListField()


class ListUsersInRoleWithScopeSerializer(ScopeMixin):  # pylint: disable=abstract-method
    """Serializer for listing users in a role with a scope."""

    roles = CommaSeparatedListField(required=False)


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


class RoleAssignmentSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """Serializer for a role assignment."""

    username = serializers.SerializerMethodField()
    full_name = serializers.SerializerMethodField()
    email = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._user_cache = {}

    def _get_user(self, obj):
        """Cache user lookups to avoid duplicate DB queries."""
        username = obj.subject.username
        if username not in self._user_cache:
            self._user_cache[username] = get_user_by_username_or_email(username)
        return self._user_cache[username]

    def get_username(self, obj):
        return obj.subject.username

    def get_full_name(self, obj):
        return self._get_user(obj).profile.name

    def get_email(self, obj):
        return self._get_user(obj).email

    def get_roles(self, obj):
        return [role.external_key for role in obj.roles]
