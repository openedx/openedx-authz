from django.apps import AppConfig
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


class CasbinAdapterConfig(AppConfig):
    name = "casbin_adapter"

    def ready(self):
        """Initialization layer for the casbin_adapter app."""
        # DO NOT initialize the enforcer here to avoid issues when
        # apps are not fully loaded (e.g., while pulling translations).
        # It's best to lazy load the enforcer when needed it's first used.
        pass
