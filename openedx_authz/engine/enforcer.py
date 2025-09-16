"""
Extended Casbin enforcer with watcher integration.
"""

import logging

from casbin import FastEnforcer
from django.conf import settings

from openedx_authz.engine.adapter import ExtendedAdapter
from openedx_authz.engine.watcher import Watcher

logger = logging.getLogger(__name__)

adapter = ExtendedAdapter()
enforcer = FastEnforcer(settings.CASBIN_MODEL, adapter, enable_log=False)

try:
    enforcer.set_watcher(Watcher)
    logger.info("Watcher successfully set on Casbin enforcer")
except Exception as e:  # pylint: disable=broad-exception-caught
    logger.error(f"Failed to set watcher on Casbin enforcer: {e}")
