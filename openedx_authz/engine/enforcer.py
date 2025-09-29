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

from openedx_authz.engine.adapter import ExtendedAdapter
from openedx_authz.engine.watcher import Watcher

logger = logging.getLogger(__name__)

adapter = ExtendedAdapter()
enforcer = FastEnforcer(settings.CASBIN_MODEL, adapter, enable_log=True)
enforcer.enable_auto_save(True)

if Watcher:
    try:
        enforcer.set_watcher(Watcher)
        logger.info("Watcher successfully set on Casbin enforcer")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error(f"Failed to set watcher on Casbin enforcer: {e}")
