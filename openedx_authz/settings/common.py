"""
Common settings for openedx_authz plugin.
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
    casbin_adapter_app = "openedx_authz.engine.apps.CasbinAdapterConfig"
    if casbin_adapter_app not in settings.INSTALLED_APPS:
        settings.INSTALLED_APPS.append(casbin_adapter_app)
    # Add Casbin configuration
    if not getattr(settings, "CASBIN_MODEL", None):
        settings.CASBIN_MODEL = os.path.join(ROOT_DIRECTORY, "engine", "config", "model.conf")
    if not getattr(settings, "CASBIN_POLICY_DEFAULTS", None):
        settings.CASBIN_POLICY_DEFAULTS = os.path.join(ROOT_DIRECTORY, "engine", "config", "authz.policy")
    if not getattr(settings, "CASBIN_WATCHER_ENABLED", None):
        settings.CASBIN_WATCHER_ENABLED = False

    # TODO: Replace with a more dynamic configuration
    # Redis host and port are temporarily loaded here for the MVP
    if not getattr(settings, "CASBIN_WATCHER_REDIS_HOST", None):
        settings.CASBIN_WATCHER_REDIS_HOST = "redis"
    if not getattr(settings, "CASBIN_WATCHER_REDIS_PORT", None):
        settings.CASBIN_WATCHER_REDIS_PORT = 6379
