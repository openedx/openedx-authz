"""openedx-authz's own static authorization schema resources.

This package ships the platform-default schema files under ``authz/schema`` and
exposes that directory through the ``authz.schema`` entry point (ADR 0019).
openedx-authz is a schema provider like any other distribution; its directory is
discovered the same way a third-party application's would be, and the loader
reads every ``.yaml`` file inside it.

Register in setup.py / pyproject.toml::

    entry_points = {
        "authz.schema": [
            "openedx_authz = openedx_authz.authz:get_schema_resources",
        ],
    }
"""

from __future__ import annotations

# Directory paths (relative to an importable top-level package) that contain
# this distribution's ``.yaml`` schema files. Per ADR 0019, providers return
# directories, not individual files.
SCHEMA_DIRECTORIES: tuple[str, ...] = ("openedx_authz/authz/schema",)


def get_schema_resources() -> list[str]:
    """Return this package's schema directory paths.

    The ``authz.schema`` entry point points at this callable; the discovery
    step resolves each returned directory via ``importlib.resources`` and loads
    every ``.yaml`` file it contains.
    """
    return list(SCHEMA_DIRECTORIES)
