"""
Open edX AuthZ provides the architecture and foundations of the authorization framework.
"""

import os
from importlib.metadata import version as get_version

ROOT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))

__version__ = get_version("openedx-authz")
