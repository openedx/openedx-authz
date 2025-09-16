"""
Extended Casbin enforcer.
"""

import os

from casbin import FastEnforcer

from openedx_authz import ROOT_DIRECTORY
from openedx_authz.engine.adapter import ExtendedAdapter

model_file = os.path.join(ROOT_DIRECTORY, "engine", "model.conf")
policy_file = os.path.join(ROOT_DIRECTORY, "engine", "policy.csv")

adapter = ExtendedAdapter()
enforcer = FastEnforcer(model_file, adapter)
