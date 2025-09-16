"""
Common settings for openedx_authz plugin.
"""

import os

from redis_watcher import WatcherOptions, new_watcher

from openedx_authz import ROOT_DIRECTORY


def callback_function(event):
    """
    Callback function for the enforcer.
    """
    print("\nCallback function for the enforcer, event: {}".format(event))


def plugin_settings(settings):
    """
    Configure plugin settings for Open edX.
    This function is called by the Open edX plugin system to configure
    the Django settings for this plugin.

    Args:
        settings: The Django settings object
    """
    # Add external third-party apps to INSTALLED_APPS
    casbin_adapter_app = "casbin_adapter.apps.CasbinAdapterConfig"
    if casbin_adapter_app not in settings.INSTALLED_APPS:
        settings.INSTALLED_APPS.append(casbin_adapter_app)

    # Add Casbin configuration
    settings.CASBIN_MODEL = os.path.join(ROOT_DIRECTORY, "model.conf")
    watcher_options = WatcherOptions()
    watcher_options.host = "redis"
    watcher_options.port = 6379
    watcher_options.optional_update_callback = callback_function
    watcher = new_watcher(watcher_options)
    settings.CASBIN_WATCHER = watcher
    settings.CASBIN_ADAPTER = "openedx_authz.engine.adapter.ExtendedAdapter"
