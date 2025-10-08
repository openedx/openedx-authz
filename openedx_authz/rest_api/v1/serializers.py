"""Serializers for the Open edX AuthZ REST API."""

from django.contrib.auth import get_user_model
from rest_framework import serializers

from openedx_authz.api.data import RoleAssignmentData
from openedx_authz.rest_api.enums import SortField, SortOrder
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


class AddUsersToRoleWithScopeSerializer(RoleMixin, ScopeMixin):  # pylint: disable=abstract-method
    """Serializer for adding users to a role with a scope."""

    users = serializers.ListField(child=serializers.CharField(max_length=255), allow_empty=False)


class RemoveUsersFromRoleWithScopeSerializer(RoleMixin, ScopeMixin):  # pylint: disable=abstract-method
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

    def get_username(self, obj: RoleAssignmentData) -> str:
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

    def get_roles(self, obj: RoleAssignmentData) -> list[str]:
        """Get the roles for the given role assignment."""
        return [role.external_key for role in obj.roles]
