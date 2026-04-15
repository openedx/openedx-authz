"""Admin configuration for openedx_authz."""

import json

from casbin_adapter.models import CasbinRule
from django import forms
from django.contrib import admin
from django.utils.html import format_html

from openedx_authz.api.data import ContentLibraryData, CourseOverviewData
from openedx_authz.models import AuthzCourseAuthoringMigrationRun, ExtendedCasbinRule
from openedx_authz.models.core import RoleAssignmentAudit


def pretty_json(value) -> str:
    """Return an indented JSON representation of a value."""
    if value is None:
        return "-"
    try:
        formatted = json.dumps(value, indent=2, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)
    return format_html("<pre>{}</pre>", formatted)


class CasbinRuleForm(forms.ModelForm):
    """Custom form for CasbinRule to make v3, v4, v5 fields optional."""

    class Meta:
        """Meta class for CasbinRuleForm."""

        model = CasbinRule
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        """Initialize CasbinRuleForm."""
        super().__init__(*args, **kwargs)
        # Make v2, v3, v4, v5 optional in the form
        # These fields are not always required depending on the policy type
        self.fields["v2"].required = False
        self.fields["v3"].required = False
        self.fields["v4"].required = False
        self.fields["v5"].required = False


class ExtendedCasbinRuleInline(admin.StackedInline):
    """Inline admin for ExtendedCasbinRule to display additional metadata."""

    model = ExtendedCasbinRule
    extra = 0
    fields = ("casbin_rule_key", "scope", "subject", "description", "metadata", "created_at", "updated_at")
    readonly_fields = ("casbin_rule_key", "scope", "subject", "created_at", "updated_at")
    can_delete = False


@admin.register(CasbinRule)
class CasbinRuleAdmin(admin.ModelAdmin):
    """Admin for CasbinRule to display additional metadata."""

    form = CasbinRuleForm
    list_display = ("id", "ptype", "v0", "v1", "v2", "v3", "v4", "v5")
    search_fields = ("ptype", "v0", "v1", "v2", "v3", "v4", "v5")
    list_filter = ("ptype",)
    # TODO: In a future, possibly we should only show an inline for the rules that
    # have an extended rule, and show the subject and scope information in detail.
    inlines = [ExtendedCasbinRuleInline]


@admin.register(AuthzCourseAuthoringMigrationRun)
class AuthzCourseAuthoringMigrationRunAdmin(admin.ModelAdmin):
    """Admin for AuthzCourseAuthoringMigrationRun to display additional metadata."""

    list_display = ("id", "scope_type", "scope_key", "migration_type", "status", "created_at", "updated_at")
    search_fields = ("scope_type", "scope_key", "migration_type", "status")
    list_filter = ("scope_type", "migration_type", "status")
    readonly_fields = (
        "scope_type",
        "scope_key",
        "migration_type",
        "status",
        "pretty_metadata",
        "completed_at",
        "created_at",
        "updated_at",
    )
    fields = readonly_fields

    @admin.display(description="Metadata")
    def pretty_metadata(self, obj):
        """Return formatted JSON for the metadata field."""
        return pretty_json(obj.metadata)


class ScopeTypeFilter(admin.SimpleListFilter):
    """Filter audit records by scope type (content library, course, etc.)."""

    title = "scope type"
    parameter_name = "scope_type"

    def lookups(self, request, model_admin):
        """Return the available scope type choices.

        Audit records are independent from live Casbin tables and scope objects:
        there are no FK references to filter on. The namespace prefix in the
        stored ``scope`` string (e.g. ``lib^``, ``course-v1^``) is the only
        available signal for categorizing records by scope type.
        """
        return [
            (ContentLibraryData.NAMESPACE, "Content Library"),
            (CourseOverviewData.NAMESPACE, "Course"),
        ]

    def queryset(self, request, queryset):
        """Filter the queryset by scope namespace prefix."""
        if self.value():
            return queryset.for_scope_namespace(self.value())
        return queryset


@admin.register(RoleAssignmentAudit)
class RoleAssignmentAuditAdmin(admin.ModelAdmin):
    """Read-only admin for the role assignment audit log."""

    list_display = ("operation", "display_subject", "display_role", "display_scope", "actor", "timestamp")
    list_filter = ("operation", ScopeTypeFilter)
    search_fields = ("subject", "role", "scope")
    date_hierarchy = "timestamp"
    readonly_fields = ("operation", "subject", "role", "scope", "actor", "timestamp")

    @admin.display(description="subject")
    def display_subject(self, obj):
        """Subject key without the namespace prefix."""
        return obj.subject_display

    @admin.display(description="role")
    def display_role(self, obj):
        """Role name without the namespace prefix."""
        return obj.role_display

    @admin.display(description="scope")
    def display_scope(self, obj):
        """Scope key without the namespace prefix."""
        return obj.scope_display

    def has_add_permission(self, request):
        """Audit records are created by the system only."""
        return False

    def has_change_permission(self, request, obj=None):
        """Audit records must not be modified after creation."""
        return False

    def has_delete_permission(self, request, obj=None):
        """Audit records must not be deleted through the admin."""
        return False
