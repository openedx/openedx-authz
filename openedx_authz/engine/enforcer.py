"""
Core authorization enforcer for Open edX AuthZ system.

Provides a Casbin FastEnforcer instance with extended adapter for database policy
storage and Redis watcher for distributed policy synchronization.

Components:
    - Enforcer: Main FastEnforcer instance for policy evaluation
    - Adapter: ExtendedAdapter for filtered database policy loading
    - Watcher: Redis-based watcher for real-time policy updates

Usage:
    from openedx_authz.engine.enforcer import enforcer
    allowed = enforcer.enforce(user, resource, action)

Requires `CASBIN_MODEL` setting and Redis configuration for watcher functionality.
"""

import logging

from casbin import FastEnforcer
from django.conf import settings

from openedx_authz.engine import adapter
from openedx_authz.engine.adapter import ExtendedAdapter
from openedx_authz.engine.watcher import Watcher

logger = logging.getLogger(__name__)


class AuthzEnforcer:
    """Singleton class to manage the Casbin FastEnforcer instance.

    Ensures a single enforcer instance is created safely and configured with the
    ExtendedAdapter and Redis watcher for policy management and synchronization.
    """

    enforcer = None

    def __new__(cls):
        """Singleton pattern to ensure a single enforcer instance."""
        if cls.enforcer is None:
            cls.enforcer = cls.initialize_enforcer()
        return cls.enforcer

    def initialize_enforcer(self) -> FastEnforcer:
        """
        Create and configure the Casbin FastEnforcer instance.

        This function initializes the Casbin FastEnforcer with the ExtendedAdapter
        for database-backed policy storage and sets up the Redis watcher for
        real-time policy synchronization.

        Returns:
            FastEnforcer: Configured Casbin enforcer with adapter and watcher
        """
        adapter = ExtendedAdapter()
        enforcer = FastEnforcer(settings.CASBIN_MODEL, adapter, enable_log=True)
        enforcer.enable_auto_save(True)

        if Watcher:
            try:
                enforcer.set_watcher(Watcher)
                logger.info("Watcher successfully set on Casbin enforcer")
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error(f"Failed to set watcher on Casbin enforcer: {e}")

        return enforcer
