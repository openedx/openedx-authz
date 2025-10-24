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
    def get_enforcer(cls) -> SyncedEnforcer:
        """Get the enforcer instance, creating it if needed.

        Returns:
            SyncedEnforcer: The singleton enforcer instance.
        """
        if cls._enforcer is None:
            cls._enforcer = cls._initialize_enforcer()
        return cls._enforcer

    @staticmethod
    def _initialize_enforcer() -> SyncedEnforcer:
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
        auto_load_policy_interval = getattr(settings, "CASBIN_AUTO_LOAD_POLICY_INTERVAL", 0)
        if auto_load_policy_interval > 0:
            enforcer.start_auto_load_policy(auto_load_policy_interval)
            enforcer.enable_auto_save(True)
        else:
            # Disable auto-save to prevent unnecessary database writes
            enforcer.enable_auto_save(False)

        return enforcer
