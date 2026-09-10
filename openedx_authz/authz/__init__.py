"""openedx-authz's own static authorization schema resources.

This package ships the platform-default ``.authz.yaml`` files and exposes them
through the ``authz.schema`` entry point (ADR 0019). openedx-authz is a schema
provider like any other distribution; its files are discovered the same way a
third-party application's would be.

Register in setup.py / pyproject.toml::

    entry_points = {
        "authz.schema": [
            "openedx_authz = openedx_authz.authz:get_schema_resources",
        ],
    }
"""

from __future__ import annotations

# Resource paths are relative to this module (``openedx_authz.authz``), which
# keeps discovery independent of virtualenv/container layout (ADR 0019).
SCHEMA_RESOURCES: tuple[str, ...] = (
    "library_permissions.authz.yaml",
    "library_roles.authz.yaml",
    "course_permissions.authz.yaml",
    "course_roles.authz.yaml",
)


def get_schema_resources() -> list[str]:
    """Return this package's schema resource paths (relative to this module).

    The ``authz.schema`` entry point points at this callable; the discovery
    step resolves the returned paths via ``importlib.resources``.
    """
    return list(SCHEMA_RESOURCES)
