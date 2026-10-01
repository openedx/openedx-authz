"""Typed schema objects and source records for the authz schema pipeline.

These dataclasses are the data contract passed between lifecycle steps
(ADR 0018): discovery produces :class:`DiscoveredResource`, loading produces
:class:`SchemaDocument`, and compilation produces :class:`CompiledSchema`.

The types are split into category modules for readability, but the package
preserves a flat public surface: import everything directly from
``openedx_authz.engine.schema.types``.

    * :mod:`~openedx_authz.engine.schema.types.definitions` - author-facing
      definition objects (categories, permissions, roles, role extensions).
    * :mod:`~openedx_authz.engine.schema.types.loading` - provenance
      (``SourceRecord``) and the per-file ``load`` output (``SchemaDocument``).
    * :mod:`~openedx_authz.engine.schema.types.compilation` - the resolved
      ``compile`` output (``CompiledSchema`` and friends).

Definition field shapes follow ``docs/references/authorization-schema.rst``
(reference PR): identifiers match ``[a-z][a-z0-9_]*``, permission IDs join
``namespace`` and ``name`` with a period, and the internal Casbin forms
(``act^...``, ``role^...``) never appear here.
"""

from __future__ import annotations

from openedx_authz.engine.schema.types.compilation import (
    CompiledDefinition,
    CompiledSchema,
    RelationshipSource,
)
from openedx_authz.engine.schema.types.definitions import (
    PermissionCategory,
    PermissionDefinition,
    RoleDefinition,
    RoleExtension,
)
from openedx_authz.engine.schema.types.loading import (
    SchemaDocument,
    SourceRecord,
)

__all__ = [
    # definitions
    "PermissionCategory",
    "PermissionDefinition",
    "RoleDefinition",
    "RoleExtension",
    # loading
    "SourceRecord",
    "SchemaDocument",
    # compilation
    "RelationshipSource",
    "CompiledDefinition",
    "CompiledSchema",
]
