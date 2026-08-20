"""
Open edX AuthZ provides the architecture and foundations of the authorization framework.
"""

import os
from importlib.metadata import PackageNotFoundError, version

ROOT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))

try:
    __version__ = version("openedx-authz")
except PackageNotFoundError:  # pragma: no cover
    pass
