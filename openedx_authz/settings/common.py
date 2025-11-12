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

    # Casbin settings for model and policy synchronization

    # Set default CASBIN_MODEL if not already set, this points to the model.conf file
    # which defines the access control model for Casbin.
    if not hasattr(settings, "CASBIN_MODEL"):
        settings.CASBIN_MODEL = os.path.join(ROOT_DIRECTORY, "engine", "config", "model.conf")

    # Set default CASBIN_AUTO_LOAD_POLICY_INTERVAL if not already set.
    # This setting defines how often (in seconds) the Casbin enforcer should
    # automatically reload policies from the database.
    if not hasattr(settings, "CASBIN_AUTO_LOAD_POLICY_INTERVAL"):
        settings.CASBIN_AUTO_LOAD_POLICY_INTERVAL = 0

    # Set default CASBIN_AUTO_SAVE_POLICY if not already set.
    # This setting defines whether the Casbin enforcer should automatically
    # save policy changes back to the database.
    if not hasattr(settings, "CASBIN_AUTO_SAVE_POLICY"):
        settings.CASBIN_AUTO_SAVE_POLICY = True

    # Set default ContentLibrary model for swappable dependency
    if not hasattr(settings, "OPENEDX_AUTHZ_CONTENT_LIBRARY_MODEL"):
        settings.OPENEDX_AUTHZ_CONTENT_LIBRARY_MODEL = "content_libraries.ContentLibrary"
