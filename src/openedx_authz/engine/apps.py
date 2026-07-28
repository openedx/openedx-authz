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
        """Initialize the casbin_adapter app.

        The upstream casbin_adapter app tries to initialize the enforcer
        when the app is loaded, which can lead to issues if the database is not
        ready (e.g., while pulling translations). To avoid this, we override
        the ready method and do not initialize the enforcer here.
        """
