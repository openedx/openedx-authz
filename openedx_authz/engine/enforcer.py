"""
Core authorization enforcer for Open edX AuthZ system.

Provides a Casbin SyncedEnforcer instance with extended adapter for database policy
storage and automatic policy synchronization.

Components:
    - Enforcer: Main SyncedEnforcer instance for policy evaluation
    - Adapter: ExtendedAdapter for filtered database policy loading

Usage:
    from openedx_authz.engine.enforcer import AuthzEnforcer
    allowed = enforcer.enforce(user, resource, action)

Requires `CASBIN_MODEL` setting.
"""

import logging

from casbin import SyncedEnforcer
from casbin_adapter.enforcer import initialize_enforcer
from django.conf import settings

from openedx_authz.engine.adapter import ExtendedAdapter

try:
    from cms.djangoapps.contentstore.toggles import libraries_v2_enabled
except ImportError:
    # If the CMS is not available, define a dummy toggle that is always enabled
    def libraries_v2_enabled() -> bool:
        """Dummy toggle that is always enabled."""
        return True


logger = logging.getLogger(__name__)


class AuthzEnforcer:
    """Singleton class to manage the Casbin SyncedEnforcer instance.

    Ensures a single enforcer instance is created safely and configured with the
    ExtendedAdapter for policy management and automatic synchronization.

    There are two main use cases for this class:

    1. Directly get the enforcer instance and initialize it if needed::

        from openedx_authz.engine.enforcer import AuthzEnforcer
        enforcer = AuthzEnforcer.get_enforcer()
        allowed = enforcer.enforce(user, resource, action)

    2. Instantiate the class to get the singleton enforcer instance::

        from openedx_authz.engine.enforcer import AuthzEnforcer
        enforcer = AuthzEnforcer()
        allowed = enforcer.get_enforcer().enforce(user, resource, action)

    Any of the two approaches will yield the same singleton enforcer instance.
    """

    _enforcer = None

    def __new__(cls):
        """Singleton pattern to ensure a single enforcer instance."""
        if cls._enforcer is None:
            cls._enforcer = cls._initialize_enforcer()
        return cls._enforcer

    @classmethod
    def configure_enforcer_auto_loading(cls, auto_load_policy_interval: int = None):
        """Enable auto-load policy and auto-save on the enforcer.

        This method ensures that the singleton enforcer instance is created
        and ready for use.

        Returns:
            None
        """
        if not cls._enforcer.is_auto_loading_running():
            cls._enforcer.start_auto_load_policy(auto_load_policy_interval)

    @classmethod
    def is_auto_save_enabled(cls) -> bool:
        """Check if auto-save is currently enabled on the enforcer.

        Returns:
            bool: True if auto-save is enabled, False otherwise
        """
        if cls._enforcer is None:
            return False
        return cls._enforcer._e.auto_save  # pylint: disable=protected-access

    @classmethod
    def configure_enforcer_auto_save(cls, auto_save_policy: bool):
        """Configure auto-save on the enforcer.

        This method ensures that auto-save is enabled or disabled based on
        the auto_save_policy parameter.

        Args:
            auto_save_policy: True to enable auto-save, False to disable

        Returns:
            None
        """
        if cls.is_auto_save_enabled() != auto_save_policy:
            cls._enforcer.enable_auto_save(auto_save_policy)

    @classmethod
    def deactivate_enforcer(cls):
        """Deactivate the current enforcer instance, if any.

        This method stops the auto-load policy thread. It can be used in testing
        or when re-initialization of the enforcer is needed. IT DOES NOT
        clear the singleton instance to avoid initializing it again unintentionally.

        Returns:
            None
        """
        if cls._enforcer is not None:
            try:
                cls._enforcer.stop_auto_load_policy()
                cls._enforcer.enable_auto_save(False)
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error(f"Error stopping auto-load policy thread: {e}")

    @classmethod
    def configure_enforcer_auto_save_and_load(cls):
        """Enable auto-load policy and auto-save on the enforcer.

        This method ensures that the singleton enforcer instance is configured
        for auto-load and auto-save based on settings.

        Returns:
            None
        """
        auto_load_policy_interval = getattr(settings, "CASBIN_AUTO_LOAD_POLICY_INTERVAL", 0)
        auto_save_policy = getattr(settings, "CASBIN_AUTO_SAVE_POLICY", True)

        if auto_load_policy_interval > 0:
            cls.configure_enforcer_auto_loading(auto_load_policy_interval)
        else:
            logger.warning("CASBIN_AUTO_LOAD_POLICY_INTERVAL is not set or zero; auto-load is disabled.")

        cls.configure_enforcer_auto_save(auto_save_policy)

    @classmethod
    def get_enforcer(cls) -> SyncedEnforcer:
        """Get the enforcer instance, creating it if needed.

        Returns:
            SyncedEnforcer: The singleton enforcer instance.
        """
        if cls._enforcer is None:
            cls._enforcer = cls._initialize_enforcer()

        # HACK: This code block will only be useful when in Ulmo to deactivate
        # the enforcer when the new library experience is disabled. It should be
        # removed for the next release cycle.
        # When replaced, we will only need to configure the enforcer here. Which
        # is in charge of enabling/disabling auto-load and auto-save.
        if libraries_v2_enabled():
            cls.configure_enforcer_auto_save_and_load()
        else:
            cls.deactivate_enforcer()

        return cls._enforcer

    @classmethod
    def _initialize_enforcer(cls) -> SyncedEnforcer:
        """
        Create and configure the Casbin SyncedEnforcer instance.

        This method initializes the SyncedEnforcer with the ExtendedAdapter
        for database policy storage and automatic policy synchronization.
        It also initializes the enforcer with the specified database alias from settings.

        Returns:
            SyncedEnforcer: Configured Casbin enforcer with adapter and auto-sync
        """
        db_alias = getattr(settings, "CASBIN_DB_ALIAS", "default")

        try:
            # Initialize the enforcer with the specified database alias to set up the adapter.
            # Best to lazy load it when it's first used to ensure the database is ready and avoid
            # issues when the app is not fully loaded (e.g., while pulling translations, etc.).
            initialize_enforcer(db_alias)
        except Exception as e:
            logger.error(f"Failed to initialize Casbin enforcer with DB alias '{db_alias}': {e}")
            raise

        adapter = ExtendedAdapter()
        enforcer = SyncedEnforcer(settings.CASBIN_MODEL, adapter)

        return enforcer
