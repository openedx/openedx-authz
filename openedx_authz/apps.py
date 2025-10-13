"""
openedx_authz Django application initialization.
"""

from django.apps import AppConfig
from django.core.exceptions import ImproperlyConfigured


class OpenedxAuthzConfig(AppConfig):
    """
    Configuration for the openedx_authz Django application.
    """

    name = "openedx_authz"
    verbose_name = "Open edX AuthZ"
    default_auto_field = "django.db.models.BigAutoField"
    plugin_app = {
        "url_config": {
            "lms.djangoapp": {
                "namespace": "openedx-authz",
                "regex": r"^api/",
                "relative_path": "urls",
            },
            "cms.djangoapp": {
                "namespace": "openedx-authz",
                "regex": r"^api/",
                "relative_path": "urls",
            },
        },
        "settings_config": {
            "lms.djangoapp": {
                "test": {"relative_path": "settings.test"},
                "common": {"relative_path": "settings.common"},
                "production": {"relative_path": "settings.production"},
            },
            "cms.djangoapp": {
                "test": {"relative_path": "settings.test"},
                "common": {"relative_path": "settings.common"},
                "production": {"relative_path": "settings.production"},
            },
        },
    }

    def ready(self):
        """Initialization layer for the openedx_authz app."""
        # Initialize the enforcer to ensure it's ready when the app starts
        try:
            from openedx_authz.engine.enforcer import AuthzEnforcer
            AuthzEnforcer()
        except ImproperlyConfigured:
            # The app might not be fully configured yet (e.g., during migrations).
            # In such cases, we skip the enforcer initialization.
            pass
