"""Serializers for the Admin Console REST API views."""

from opaque_keys.edx.locator import LibraryLocatorV2
from organizations.serializers import OrganizationSerializer
from rest_framework import serializers

from openedx_authz import api
from openedx_authz.api.data import UserAssignments
from openedx_authz.rest_api.data import (
    AssignmentSortField,
    ScopesTypeField,
    UserAssignmentSortField,
)
from openedx_authz.rest_api.v1.fields import (
    CaseSensitiveCommaSeparatedListField,
    CommaSeparatedListField,
    LowercaseCharField,
)
from openedx_authz.rest_api.v1.serializers import OrderMixin


class OrgMixin(serializers.Serializer):  # pylint: disable=abstract-method
    """Mixin providing org field functionality."""

    org = serializers.CharField(required=False, max_length=255)


class ListScopesQuerySerializer(OrgMixin):  # pylint: disable=abstract-method
    """Serializer for validating query parameters in ScopesAPIView."""

    management_permission_only = serializers.BooleanField(required=False, default=False)
    scope_type = serializers.ChoiceField(
        choices=[(e.value, e.name) for e in ScopesTypeField], required=False, default=None, allow_null=True
    )
    search = serializers.CharField(required=False, default="", allow_blank=True)
    orgs = CaseSensitiveCommaSeparatedListField(required=False, default=[])


class ListTeamMembersSerializer(OrderMixin):  # pylint: disable=abstract-method
    """
    Serializer for listing team members.
    This serializer is TeamMembersAPIView, which is used in the Admin Console.
    In this content, a team member is anyone with studio access.
    """

    ASSIGNMENTS_LIMIT_DEFAULT = 3
    ASSIGNMENTS_LIMIT_MAX = 10

    roles = CommaSeparatedListField(required=False, default=[])
    scopes = CaseSensitiveCommaSeparatedListField(required=False, default=[])
    orgs = CaseSensitiveCommaSeparatedListField(required=False, default=[])
    search = LowercaseCharField(required=False, default=None)
    assignments_limit = serializers.IntegerField(required=False, default=ASSIGNMENTS_LIMIT_DEFAULT, min_value=1)

    def validate_assignments_limit(self, value: int) -> int:
        """Cap assignments_limit to the maximum allowed value."""
        return min(value, self.ASSIGNMENTS_LIMIT_MAX)


class TeamMemberSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """
    Serializer for team members.
    This serializer is APIs used by the Admin Console.
    In this content, a team member is anyone with studio access.
    """

    username = serializers.SerializerMethodField()
    full_name = serializers.SerializerMethodField()
    email = serializers.SerializerMethodField()
    assignment_count = serializers.SerializerMethodField()
    assignments = serializers.SerializerMethodField()

    def get_username(self, obj: UserAssignments) -> str:
        """Get the username for the given role assignment."""
        return getattr(obj.user, "username", "") if obj.user else ""

    def get_full_name(self, obj: UserAssignments) -> str:
        """Get the full name from the UserProfile."""
        user = obj.user
        return getattr(user.profile, "name", "") if user and hasattr(user, "profile") else ""

    def get_email(self, obj: UserAssignments) -> str:
        """Get the email for the given role assignment."""
        return getattr(obj.user, "email", "") if obj.user else ""

    def get_assignment_count(self, obj: UserAssignments) -> int:
        """Get the assignment count for the given role assignment."""
        return len(obj.assignments)

    def get_assignments(self, obj: UserAssignments) -> list[dict]:
        """Return the first N assignment records, limited by assignments_limit from context."""
        limit = self.context.get("assignments_limit", ListTeamMembersSerializer.ASSIGNMENTS_LIMIT_DEFAULT)
        limited_assignments = obj.assignments[:limit]
        return TeamMemberAssignmentInlineSerializer(
            limited_assignments,
            many=True,
        ).data


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
                if obj.scope.IS_PLATFORM_GLOB:
                    return "*"
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


class TeamMemberAssignmentInlineSerializer(TeamMemberAssignmentSerializer):  # pylint: disable=abstract-method
    """Compact serializer for assignment records inlined into the team-members response.

    Reuses role, org, scope, and permission_count from TeamMemberAssignmentSerializer.
    Adds scope_display_name and drops is_superadmin which is not needed inline.
    """

    scope_display_name = serializers.SerializerMethodField()

    def get_scope_display_name(self, _obj: api.RoleAssignmentData) -> str:
        """Return an empty placeholder; the view injects the real value post-pagination."""
        return ""

    def to_representation(self, instance):
        """Remove is_superadmin from the serialized output."""
        data = super().to_representation(instance)
        data.pop("is_superadmin", None)
        return data


class TeamMemberUserAssignmentSerializer(TeamMemberAssignmentSerializer):  # pylint: disable=abstract-method
    """Serializer for team member assignments with user information."""

    full_name = serializers.SerializerMethodField()
    username = serializers.SerializerMethodField()
    email = serializers.SerializerMethodField()

    def get_full_name(self, obj: api.UserAssignmentData | api.SuperAdminAssignmentData) -> str:
        """Get the full name from the UserProfile."""
        user = obj.user
        return getattr(user.profile, "name", "") if user and hasattr(user, "profile") else ""

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
