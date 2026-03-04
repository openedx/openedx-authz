"""Admin configuration for openedx_authz."""

from casbin_adapter.models import CasbinRule
from django import forms
from django.contrib import admin

from openedx_authz.models import ExtendedCasbinRule


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
