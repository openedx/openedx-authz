"""Admin configuration for openedx_authz."""

from casbin_adapter.models import CasbinRule
from django.contrib import admin

from openedx_authz.models import ExtendedCasbinRule


class ExtendedCasbinRuleInline(admin.StackedInline):
    """Inline admin for ExtendedCasbinRule to display additional metadata."""

    model = ExtendedCasbinRule
    extra = 0
    fields = ("casbin_rule_key", "scope", "subject", "description", "metadata", "created_at", "updated_at")
    readonly_fields = ("casbin_rule_key", "scope", "subject", "created_at", "updated_at")
    can_delete = False


@admin.register(CasbinRule)
class CasbinRuleAdmin(admin.ModelAdmin):
    list_display = ("id", "ptype", "v0", "v1", "v2", "v3", "v4", "v5")
    search_fields = ("ptype", "v0", "v1", "v2", "v3", "v4", "v5")
    list_filter = ("ptype",)
    inlines = [ExtendedCasbinRuleInline]
