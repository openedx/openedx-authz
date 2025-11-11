"""Admin configuration for openedx_authz."""

from casbin_adapter.models import CasbinRule
from django.contrib import admin


@admin.register(CasbinRule)
class CasbinRuleAdmin(admin.ModelAdmin):
    list_display = ("id", "ptype", "v0", "v1", "v2", "v3", "v4", "v5")
    search_fields = ("ptype", "v0", "v1", "v2", "v3", "v4", "v5")
    list_filter = ("ptype",)
