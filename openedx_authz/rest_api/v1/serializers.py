"""Serializers for the Open edX AuthZ REST API."""

from django.contrib.auth import get_user_model
from opaque_keys.edx.locator import LibraryLocatorV2
from organizations.serializers import OrganizationSerializer
from rest_framework import serializers

from openedx_authz import api
from openedx_authz.api.data import UserAssignments
from openedx_authz.rest_api.data import (
    AssignmentSortField,
    ScopesTypeField,
    SortField,
    SortOrder,
    UserAssignmentSortField,
)
from openedx_authz.rest_api.utils import get_generic_scope
from openedx_authz.rest_api.v1.fields import (
    CaseSensitiveCommaSeparatedListField,
    CommaSeparatedListField,
    LowercaseCharField,
)

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


class OrderMixin(serializers.Serializer):  # pylint: disable=abstract-method
    """Mixin providing ordering field functionality."""

    sort_by = serializers.ChoiceField(
        required=False,
        choices=[(e.value, e.name) for e in SortField],
        default=SortField.USERNAME,
    )
    order = serializers.ChoiceField(
        required=False,
        choices=[(e.value, e.name) for e in SortOrder],
        default=SortOrder.ASC,
    )


class OrgMixin(serializers.Serializer):  # pylint: disable=abstract-method
    """Mixin providing org field functionality."""

    org = serializers.CharField(required=False, max_length=255)


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
            raise serializers.ValidationError({"scope": str(exc)}) from exc

        if not scope.exists():
            raise serializers.ValidationError({"scope": f"Scope '{scope_value}' does not exist"})

        role = api.RoleData(external_key=role_value)
        generic_scope = get_generic_scope(scope)
        role_definitions = api.get_role_definitions_in_scope(generic_scope)

        if role not in role_definitions:
            raise serializers.ValidationError({"role": f"Role '{role_value}' does not exist in scope '{scope_value}'"})

        return validated_data


class AddUsersToRoleWithScopeSerializer(
    RoleMixin,
    ScopeMixin,
):  # pylint: disable=abstract-method
    """Serializer for adding users to a role with one or more scopes.

    Accepts either a single ``scope`` string (backward-compatible) or a
    ``scopes`` list for bulk assignment.  Exactly one of the two must be
    provided per request.
    """

    scope = serializers.CharField(max_length=255, required=False, default=None, allow_null=True)
    scopes = serializers.ListField(
        child=serializers.CharField(max_length=255),
        required=False,
        default=None,
    )
    users = serializers.ListField(child=serializers.CharField(max_length=255), allow_empty=False)

    def validate_users(self, value) -> list[str]:
        """Eliminate duplicates preserving order"""
        return list(dict.fromkeys(value))

    def validate(self, attrs) -> dict:
        """Validate that exactly one of 'scope'/'scopes' is provided and that every
        scope exists in the registry, exists in the system, and supports the role.
        Returns validated data with a unified ``scopes`` list of strings.
        """
        validated_data = super().validate(attrs)
        scope = validated_data.get("scope")
        scopes = validated_data.get("scopes")
        role_value = validated_data["role"]

        if scope and scopes is not None:
            raise serializers.ValidationError(
                "Provide either 'scope' or 'scopes', not both."
            )

        scopes_list = scopes if scopes is not None else ([scope] if scope else None)
        if not scopes_list:
            raise serializers.ValidationError(
                "Either 'scope' or 'scopes' must be provided."
            )

        validated_scopes = []
        for scope_value in scopes_list:
            try:
                scope_obj = api.ScopeData(external_key=scope_value)
            except ValueError as exc:
                raise serializers.ValidationError({"scope": str(exc)}) from exc

            if not scope_obj.exists():
                raise serializers.ValidationError({"scope": f"Scope '{scope_value}' does not exist"})

            role_obj = api.RoleData(external_key=role_value)
            generic_scope = get_generic_scope(scope_obj)
            role_definitions = api.get_role_definitions_in_scope(generic_scope)

            if role_obj not in role_definitions:
                raise serializers.ValidationError(
                    {"role": f"Role '{role_value}' does not exist in scope '{scope_value}'"}
                )

            validated_scopes.append(scope_value)

        validated_data.pop("scope", None)
        validated_data["scopes"] = validated_scopes
        return validated_data


class RemoveUsersFromRoleWithScopeSerializer(
    RoleScopeValidationMixin,
    RoleMixin,
    ScopeMixin,
):  # pylint: disable=abstract-method
    """Serializer for removing users from a role with a scope."""

    users = CommaSeparatedListField(allow_blank=False)


class ListUsersInRoleWithScopeSerializer(ScopeMixin, OrderMixin):  # pylint: disable=abstract-method
    """Serializer for listing users in a role with a scope."""

    roles = CommaSeparatedListField(required=False, default=[])
    search = LowercaseCharField(required=False, default=None)


class ListRolesWithScopeSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """Serializer for listing roles within a scope."""

    scope = serializers.CharField(max_length=255)

    def validate_scope(self, value: str) -> api.ScopeData:
        """Validate and convert scope string to a ScopeData instance.

        Checks that the provided scope is registered in the scope registry and
        returns an instance of the appropriate ScopeData subclass.

        Args:
            value: The scope string to validate (e.g., 'lib', 'global', 'org').

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


class ListScopesQuerySerializer(OrgMixin):  # pylint: disable=abstract-method
    """Serializer for validating query parameters in ScopesAPIView."""

    management_permission_only = serializers.BooleanField(required=False, default=False)
    scope_type = serializers.ChoiceField(
        choices=[(e.value, e.name) for e in ScopesTypeField], required=False, default=None, allow_null=True
    )
    search = serializers.CharField(required=False, default="", allow_blank=True)


class ListTeamMembersSerializer(OrderMixin):  # pylint: disable=abstract-method
    """
    Serializer for listing team members.
    This serializer is TeamMembersAPIView, which is used in the Admin Console.
    In this content, a team member is anyone with studio access.
    """

    scopes = CaseSensitiveCommaSeparatedListField(required=False, default=[])
    orgs = CaseSensitiveCommaSeparatedListField(required=False, default=[])
    search = LowercaseCharField(required=False, default=None)


class TeamMemberSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """
    Serializer for team members.
    This serializer is APIs used by the Admin Console.
    In this content, a team member is anyone with studio access.
    """

    username = serializers.SerializerMethodField()
    full_name = serializers.SerializerMethodField()
    email = serializers.SerializerMethodField()
    assignation_count = serializers.SerializerMethodField()

    def get_username(self, obj: UserAssignments) -> str:
        """Get the username for the given role assignment."""
        return getattr(obj.user, "username", "") if obj.user else ""

    def get_full_name(self, obj: UserAssignments) -> str:
        """Get the full name for the given role assignment."""
        return obj.user.get_full_name() if obj.user else ""

    def get_email(self, obj: UserAssignments) -> str:
        """Get the email for the given role assignment."""
        return getattr(obj.user, "email", "") if obj.user else ""

    def get_assignation_count(self, obj: UserAssignments) -> int:
        """Get the assignation count for the given role assignment."""
        return len(obj.assignments)


class UserValidationAPIViewSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """Serializer for validating user existence."""

    users = serializers.ListField(
        child=serializers.CharField(max_length=255), allow_empty=False, help_text="List of user identifiers to validate"
    )

    def validate_users(self, value) -> list[str]:
        """Eliminate duplicates preserving order"""
        return list(dict.fromkeys(value))


class UserValidationSummarySerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """Serializer for user validation summary statistics."""

    total = serializers.IntegerField(help_text="Total number of users validated")
    valid_count = serializers.IntegerField(help_text="Number of valid users found")
    invalid_count = serializers.IntegerField(help_text="Number of invalid users")


class UserValidationAPIViewResponseSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """Serializer for user validation response."""

    valid_users = serializers.ListField(
        child=serializers.CharField(max_length=255), help_text="List of user identifiers that were found to be valid"
    )
    invalid_users = serializers.ListField(
        child=serializers.CharField(max_length=255),
        help_text="List of user identifiers that were not found or are invalid",
    )
    summary = UserValidationSummarySerializer(help_text="Summary statistics for the validation operation")


class ListTeamMemberAssignmentsQuerySerializer(OrderMixin):  # pylint: disable=abstract-method
    """Serializer for listing team member assignments."""

    orgs = CaseSensitiveCommaSeparatedListField(required=False, default=[])
    roles = CaseSensitiveCommaSeparatedListField(required=False, default=[])
    # Overriding sort_by from OrderMixin due to different choices and default value
    sort_by = serializers.ChoiceField(
        required=False,
        choices=[(e.value, e.name) for e in AssignmentSortField],
        default=AssignmentSortField.ROLE,
    )


class TeamMemberAssignmentSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """Serializer for team member assignments."""

    is_superadmin = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    org = serializers.SerializerMethodField()
    scope = serializers.SerializerMethodField()
    permission_count = serializers.SerializerMethodField()

    def get_is_superadmin(self, obj: api.RoleAssignmentData | api.SuperAdminAssignmentData) -> bool:
        """Get whether this assignment entry is for a superadmin."""
        return isinstance(obj, api.SuperAdminAssignmentData)

    def get_role(self, obj: api.RoleAssignmentData | api.SuperAdminAssignmentData) -> str:
        """Get the role for the given role assignment."""
        match obj:
            case api.SuperAdminAssignmentData():
                return "django.superuser" if obj.is_superuser else "django.staff"
            case api.RoleAssignmentData():
                return obj.roles[0].external_key if obj.roles else ""

    def get_org(self, obj: api.RoleAssignmentData | api.SuperAdminAssignmentData) -> str:
        """Get the org for the given role assignment."""
        match obj:
            case api.SuperAdminAssignmentData():
                return "*"
            case api.RoleAssignmentData():
                return getattr(obj.scope, "org", "")

    def get_scope(self, obj: api.RoleAssignmentData | api.SuperAdminAssignmentData) -> str:
        """Get the scope for the given role assignment."""
        match obj:
            case api.SuperAdminAssignmentData():
                return "*"
            case api.RoleAssignmentData():
                return obj.scope.external_key

    def get_permission_count(self, obj: api.RoleAssignmentData | api.SuperAdminAssignmentData) -> int | None:
        """Get the permission count for the given role assignment."""
        match obj:
            case api.SuperAdminAssignmentData():
                return None
            case api.RoleAssignmentData():
                return len(obj.roles[0].permissions) if obj.roles else 0


class TeamMemberUserAssignmentSerializer(TeamMemberAssignmentSerializer):  # pylint: disable=abstract-method
    """Serializer for team member assignments with user information."""

    full_name = serializers.SerializerMethodField()
    username = serializers.SerializerMethodField()
    email = serializers.SerializerMethodField()

    def get_full_name(self, obj: api.UserAssignmentData | api.SuperAdminAssignmentData) -> str:
        """Get user full name."""
        return obj.user.get_full_name() if obj.user else ""

    def get_username(self, obj: api.UserAssignmentData | api.SuperAdminAssignmentData) -> str:
        """Get username."""
        return obj.user.username if obj.user else ""

    def get_email(self, obj: api.UserAssignmentData | api.SuperAdminAssignmentData) -> str:
        """Get user email."""
        return obj.user.email if obj.user else ""


class ListAssignmentsQuerySerializer(ListTeamMemberAssignmentsQuerySerializer):  # pylint: disable=abstract-method
    """Serializer for query params for the list all team member assignments endpoint."""

    search = LowercaseCharField(required=False, default=None)
    scopes = CaseSensitiveCommaSeparatedListField(required=False, default=[])
    # Overriding sort_by from OrderMixin due to different choices and default value
    sort_by = serializers.ChoiceField(
        required=False,
        choices=[(e.value, e.name) for e in UserAssignmentSortField],
        default=UserAssignmentSortField.FULL_NAME,
    )


class ScopeSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """
    Serializer for scope.
    """

    external_key = serializers.SerializerMethodField()
    display_name = serializers.SerializerMethodField()
    org = serializers.SerializerMethodField()

    def get_external_key(self, obj: dict) -> str:
        """Get the external key for the given scope."""
        if obj["scope_type"] == ScopesTypeField.LIBRARY:
            return str(LibraryLocatorV2(org=obj["org_name"], slug=obj["scope_id"]))
        return obj["scope_id"]

    def get_display_name(self, obj: dict) -> str:
        """Get the display name for the given scope."""
        return str(obj.get("display_name_col") or "")

    def get_org(self, obj: dict) -> dict | None:
        """Get the org for the given scope."""
        org = self.context.get("org_map", {}).get(obj["org_name"])
        return OrganizationSerializer(org).data if org else None
