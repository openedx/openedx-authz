"""
Core authorization enforcer for Open edX AuthZ system.

Provides a Casbin FastEnforcer instance with extended adapter for database policy
storage and Redis watcher for distributed policy synchronization.

Components:
    - Enforcer: Main FastEnforcer instance for policy evaluation
    - Adapter: ExtendedAdapter for filtered database policy loading
    - Watcher: Redis-based watcher for real-time policy updates

Usage:
    from openedx_authz.engine.enforcer import AuthzEnforcer
    allowed = enforcer.enforce(user, resource, action)

Requires `CASBIN_MODEL` setting and Redis configuration for watcher functionality.
"""

import logging

from casbin import FastEnforcer
from casbin_adapter.enforcer import initialize_enforcer
from django.conf import settings

from openedx_authz.engine.adapter import ExtendedAdapter
from openedx_authz.engine.watcher import Watcher

logger = logging.getLogger(__name__)


class AuthzEnforcer:
    """Singleton class to manage the Casbin FastEnforcer instance.

    Ensures a single enforcer instance is created safely and configured with the
    ExtendedAdapter and Redis watcher for policy management and synchronization.

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
    def get_enforcer(cls) -> FastEnforcer:
        """Get the enforcer instance, creating it if needed.

        Returns:
            FastEnforcer: The singleton enforcer instance.
        """
        if cls._enforcer is None:
            cls._enforcer = cls._initialize_enforcer()
        return cls._enforcer

    @staticmethod
    def _initialize_enforcer() -> FastEnforcer:
        """
        Create and configure the Casbin FastEnforcer instance.

        This method initializes the FastEnforcer with the ExtendedAdapter
        for database policy storage and sets up the Redis watcher for real-time
        policy synchronization if the Watcher is available. It also initializes
        the enforcer with the specified database alias from settings.

        Returns:
            FastEnforcer: Configured Casbin enforcer with adapter and watcher
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
        enforcer = FastEnforcer(settings.CASBIN_MODEL, adapter, enable_log=True)
        enforcer.enable_auto_save(True)

        if not Watcher:
            logger.warning("Redis configuration not completed successfully. Watcher is disabled.")
            return enforcer

        try:
            enforcer.set_watcher(Watcher)
            logger.info("Watcher successfully set on Casbin enforcer")
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error(f"Failed to set watcher on Casbin enforcer: {e}")

        return enforcer
