"""
openedx_authz Django application initialization.
"""

from django.apps import AppConfig


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
