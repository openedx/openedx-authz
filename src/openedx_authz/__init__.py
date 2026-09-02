"""
Open edX AuthZ provides the architecture and foundations of the authorization framework.
"""

import os
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as get_version

ROOT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))

try:
    __version__ = get_version("openedx-authz")
except PackageNotFoundError:  # pragma: no cover
    pass
