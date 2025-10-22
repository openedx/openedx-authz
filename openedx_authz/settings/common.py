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
    settings.CASBIN_MODEL = os.path.join(
        ROOT_DIRECTORY, "engine", "config", "model.conf"
    )
    if not hasattr(settings, "CASBIN_AUTO_LOAD_POLICY_INTERVAL"):
        settings.CASBIN_AUTO_LOAD_POLICY_INTERVAL = 5
