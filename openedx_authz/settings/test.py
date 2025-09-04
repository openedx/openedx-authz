"""
Test settings for openedx_authz plugin.
"""

import os

from openedx_authz import ROOT_DIRECTORY


def plugin_settings(settings):
    """
    Configure plugin settings for Open edX.

    This function is called by the Open edX plugin system to configure
    the Django settings for this plugin.

    Args:
        settings: The Django settings object
    """
    # Add external third-party apps to INSTALLED_APPS
    external_apps = [
        "casbin_adapter.apps.CasbinAdapterConfig",  # Casbin Adapter
        "dauthz.apps.DauthzConfig",  # Django Authorization library
    ]

    for app in external_apps:
        if app not in settings.INSTALLED_APPS:
            settings.INSTALLED_APPS.append(app)

    # Add middleware for authorization
    middleware_class = "dauthz.middlewares.request_middleware.RequestMiddleware"
    settings.MIDDLEWARE = settings.MIDDLEWARE + [middleware_class]

    # Add authorization configuration
    settings.CASBIN_MODEL = os.path.join(ROOT_DIRECTORY, "model.conf")
    settings.DAUTHZ = {
        "DEFAULT": {
            "MODEL": {
                "CONFIG_TYPE": "file",
                "CONFIG_FILE_PATH": settings.CASBIN_MODEL,
                "CONFIG_TEXT": "",
            },
            "ADAPTER": {
                "NAME": "casbin_adapter.adapter.Adapter",
            },
            "LOG": {
                "ENABLED": True,
            },
        },
    }
