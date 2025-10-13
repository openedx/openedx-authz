from django.apps import AppConfig
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


class CasbinAdapterConfig(AppConfig):
    name = "casbin_adapter"

    def ready(self):
        """Initialization layer for the casbin_adapter app."""

        try:
            from casbin_adapter.enforcer import initialize_enforcer

            db_alias = getattr(settings, "CASBIN_DB_ALIAS", "default")
            initialize_enforcer(db_alias)
        except ImproperlyConfigured:
            # The app might not be fully configured yet (e.g., during migrations).
            # In such cases, we skip the enforcer initialization.
            pass
