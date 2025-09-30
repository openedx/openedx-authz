"""Serializers for the Open edX AuthZ REST API."""

from django.contrib.auth import get_user_model
from rest_framework import serializers

from openedx_authz.api.data import RoleAssignmentData
from openedx_authz.rest_api.enums import SortField, SortOrder
from openedx_authz.rest_api.utils import get_user_by_username_or_email
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


class AddUserToRoleWithScopeSerializer(RoleMixin, ScopeMixin):  # pylint: disable=abstract-method
    """Serializer for adding a user to a role with a scope."""

    users = serializers.ListField(child=serializers.CharField(max_length=255))


class RemoveUserFromRoleWithScopeSerializer(RoleMixin, ScopeMixin):  # pylint: disable=abstract-method
    """Serializer for removing a user from a role with a scope."""

    users = CommaSeparatedListField()


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

    def _get_user(self, obj: RoleAssignmentData) -> User | None:
        """
        Retrieve and cache the user object for the given role assignment to minimize database queries.

        Args:
            obj (RoleAssignmentData): The role assignment data containing the user identifier.

        Returns:
            User | None: The corresponding User object if found, otherwise None.
        """
        username = obj.subject.username
        if username not in self._user_cache:
            try:
                self._user_cache[username] = get_user_by_username_or_email(username)
            except User.DoesNotExist:
                self._user_cache[username] = None
        return self._user_cache[username]

    def get_username(self, obj: RoleAssignmentData) -> str:
        return obj.subject.username

    def get_full_name(self, obj: RoleAssignmentData) -> str:
        user = self._get_user(obj)
        if not user or not hasattr(user, "profile"):
            return ""
        return getattr(user.profile, "name", "")

    def get_email(self, obj: RoleAssignmentData) -> str:
        user = self._get_user(obj)
        if not user:
            return ""
        return getattr(user, "email", "")

    def get_roles(self, obj: RoleAssignmentData) -> list[str]:
        return [role.external_key for role in obj.roles]
