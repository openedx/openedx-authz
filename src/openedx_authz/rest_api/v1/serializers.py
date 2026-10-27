"""Serializers for the reusable Open edX AuthZ REST API."""

from django.contrib.auth import get_user_model
from rest_framework import serializers

from openedx_authz import api
from openedx_authz.api.data import GLOBAL_SCOPE_WILDCARD, DefinitionKind
from openedx_authz.rest_api.data import ScopesTypeField, SortField, SortOrder
from openedx_authz.rest_api.utils import get_generic_scope, parse_scope_types
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


class PermissionValidationSerializer(ActionMixin, ScopeMixin):  # pylint: disable=abstract-method
    """Serializer for permission validation request.

    The ``scope`` is optional: when provided, the permission is validated against that
    scope; when omitted, the permission is validated across any scope.
    """

    scope = serializers.CharField(max_length=255, required=False)


class PermissionValidationResponseSerializer(PermissionValidationSerializer):  # pylint: disable=abstract-method
    """Serializer for permission validation response."""

    allowed = serializers.BooleanField()


class RoleScopeValidationMixin(serializers.Serializer):  # pylint: disable=abstract-method
    """Mixin providing role and scope validation logic."""

    def _validate_scope_and_role(self, scope_value: str, role_value: str) -> None:
        """Validate that a single scope exists and the role is defined in it.

        Args:
            scope_value: The scope string to validate.
            role_value: The role string to validate against the scope.

        Raises:
            serializers.ValidationError: If the scope is not registered, doesn't exist,
                or if the role is not defined in the scope.
        """
        if scope_value == GLOBAL_SCOPE_WILDCARD:
            raise serializers.ValidationError(
                {"scope": "Global wildcard scope '*' is not accepted via the API. Use a specific scope key."}
            )

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
        self._validate_scope_and_role(validated_data["scope"], validated_data["role"])
        return validated_data


class AddUsersToRoleWithScopeSerializer(
    RoleScopeValidationMixin,
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
        """Eliminate duplicates preserving order."""
        return list(dict.fromkeys(value))

    def validate(self, attrs) -> dict:
        """Validate that exactly one of 'scope'/'scopes' is provided and that every
        scope exists in the registry, exists in the system, and supports the role.
        Returns validated data with a unified ``scopes`` list of strings.
        """
        validated_data = super(RoleScopeValidationMixin, self).validate(attrs)
        scope = validated_data.get("scope")
        scopes = validated_data.get("scopes")
        role_value = validated_data["role"]

        if scope and scopes is not None:
            raise serializers.ValidationError("Provide either 'scope' or 'scopes', not both.")

        scopes_list = scopes if scopes is not None else ([scope] if scope else None)
        if not scopes_list:
            raise serializers.ValidationError("Either 'scope' or 'scopes' must be provided.")

        for scope_value in scopes_list:
            self._validate_scope_and_role(scope_value, role_value)

        validated_data.pop("scope", None)
        validated_data["scopes"] = scopes_list
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


class ListUsersInRoleWithScopeResponseSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """Serializer for listing users in a role with a scope response."""

    username = serializers.CharField(max_length=255)
    full_name = serializers.CharField(max_length=255)
    email = serializers.EmailField()


class ListRolesQuerySerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """Serializer for validating the query parameters of the role catalog."""

    scope_types = serializers.CharField()

    def validate_scope_types(self, value: str) -> list[str]:
        """Convert the comma-separated scope types to a list of unique, supported scope types.

        Raises:
            serializers.ValidationError: If a value is empty or is not a supported scope type.
        """
        scope_types = parse_scope_types(value)
        if scope_types is None:
            raise serializers.ValidationError(
                f"Must be a comma-separated list of supported scope types: {', '.join(ScopesTypeField.values())}.",
                code="invalid_choice",
            )
        return scope_types


class RoleCatalogCategorySerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """A permission category of the role catalog."""

    id = serializers.CharField(source="category_id")
    display_name = serializers.CharField()
    description = serializers.CharField()
    icon = serializers.CharField(allow_null=True)


class RoleCatalogPermissionSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """A permission of the role catalog."""

    id = serializers.CharField(source="identifier")
    display_name = serializers.CharField()
    description = serializers.CharField()
    icon = serializers.CharField(allow_null=True)
    category_id = serializers.CharField(source="category.category_id", allow_null=True)
    scope_types = serializers.ListField(child=serializers.CharField(), source="scopes")


class RoleCatalogRoleSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """A role of the role catalog, referencing permissions by identifier."""

    role = serializers.CharField(max_length=255)
    display_name = serializers.CharField()
    description = serializers.CharField(allow_blank=True)
    icon = serializers.CharField(allow_null=True)
    definition_kind = serializers.ChoiceField(choices=[(e.value, e.name) for e in DefinitionKind])
    permissions = serializers.ListField(child=serializers.CharField(max_length=255))
    scope_types = serializers.ListField(child=serializers.CharField(max_length=255))


class RoleCatalogMetaSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """Metadata of the role catalog: the requested scope types and the complete catalogs."""

    scope_types = serializers.ListField(child=serializers.ChoiceField(choices=ScopesTypeField.values()))
    categories = RoleCatalogCategorySerializer(many=True)
    permissions = RoleCatalogPermissionSerializer(many=True)


class RoleCatalogResponseSerializer(RoleCatalogMetaSerializer):  # pylint: disable=abstract-method
    """Full role catalog response, used only to document it.

    The view builds the response with the paginator (``count``, ``next``, ``previous`` and ``results``)
    plus :class:`RoleCatalogMetaSerializer`.
    """

    count = serializers.IntegerField()
    next = serializers.CharField(allow_null=True)
    previous = serializers.CharField(allow_null=True)
    results = RoleCatalogRoleSerializer(many=True)


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
