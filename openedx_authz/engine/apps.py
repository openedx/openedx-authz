"""Initialization for the casbin_adapter Django application.

This overrides the default AppConfig to avoid making queries to the database
when the app is not fully loaded (e.g., while pulling translations). Moved
the initialization of the enforcer to a lazy load when it's first used.

See openedx_authz/engine/enforcer.py for the enforcer implementation.
"""

from django.apps import AppConfig


class CasbinAdapterConfig(AppConfig):
    name = "casbin_adapter"

    def ready(self):
        """Initialize the casbin_adapter app."""
        # DO NOT initialize the enforcer here to avoid issues when
        # apps are not fully loaded (e.g., while pulling translations).
        # It's best to lazy load the enforcer when needed it's first used.
