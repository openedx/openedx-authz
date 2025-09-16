"""
Extended Casbin enforcer with watcher integration.
"""

import logging
import os

from casbin import FastEnforcer

from openedx_authz import ROOT_DIRECTORY
from openedx_authz.engine.adapter import ExtendedAdapter
from openedx_authz.engine.watcher import Watcher

logger = logging.getLogger(__name__)

model_file = os.path.join(ROOT_DIRECTORY, "engine", "model.conf")
adapter = ExtendedAdapter()
enforcer = FastEnforcer(model_file, adapter, enable_log=False)

try:
    enforcer.set_watcher(Watcher)
    logger.info("Watcher successfully set on Casbin enforcer")
except Exception as e:  # pylint: disable=broad-exception-caught
    logger.error(f"Failed to set watcher on Casbin enforcer: {e}")
