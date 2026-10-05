"""Compilation-output types for the authz schema pipeline.

These dataclasses are the output of the ``compile`` step (ADR 0018): resolved
definitions keyed by stable identifier, each carrying every
:class:`~openedx_authz.engine.schema.types.loading.SourceRecord` that
contributed to it, plus the per-grant provenance the applier persists (ADR
0025).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from openedx_authz.constants import SchemaOriginKind
from openedx_authz.engine.schema.types.definitions import (
    PermissionCategory,
    PermissionDefinition,
    RoleDefinition,
)
from openedx_authz.engine.schema.types.loading import SourceRecord


@dataclass(frozen=True)
class RolePermissionSource:
    """Provenance of a single role-permission grant (ADR 0025).

    Attributes:
        source: The contributing source record.
        origin_kind: ``SchemaOriginKind.BASE`` (from the role's own definition)
            or ``SchemaOriginKind.EXTENSION`` (added by a ``role_extensions``
            entry).
        priority: The contributing file's priority.
    """

    source: SourceRecord
    origin_kind: SchemaOriginKind
    priority: int


@dataclass(frozen=True)
class CompiledDefinition:
    """A resolved definition plus every source that contributed to it.

    The kind of definition is not stored: ``definition`` is a typed union and
    :class:`CompiledSchema` already keys categories, permissions, and roles into
    separate dicts, so the kind is recoverable from context when needed.

    Attributes:
        key: The category id, permission identifier, or role id.
        definition: The resolved dataclass instance (category/permission/role).
        sources: All contributing sources, in priority-then-discovery order.
    """

    key: str
    definition: PermissionCategory | PermissionDefinition | RoleDefinition
    sources: tuple[SourceRecord, ...]


@dataclass
class CompiledSchema:
    """The full set of resolved static definitions (output of ``compile``).

    Keyed by stable identifier. This is what the renderer turns into Casbin
    ``p`` rows and what the applier persists alongside source records.
    """

    categories: dict[str, CompiledDefinition] = field(default_factory=dict)
    permissions: dict[str, CompiledDefinition] = field(default_factory=dict)
    roles: dict[str, CompiledDefinition] = field(default_factory=dict)
    # Provenance of each role-permission grant, keyed by (role_id, permission_id).
    # Populated by the compiler; consumed when persisting sources (ADR 0025).
    role_permission_sources: dict[tuple[str, str], list[RolePermissionSource]] = field(default_factory=dict)

    def role_permission_pairs(self) -> list[tuple[str, str]]:
        """Return ``(role_id, permission_identifier)`` pairs for every role.

        This is the flattened relation the renderer maps to Casbin ``p`` rows.
        Pairs are returned in a deterministic order (role id, then permission
        id) so downstream rendering and diffing are stable across runs.
        """
        pairs: list[tuple[str, str]] = []
        for role_id in sorted(self.roles):
            role = self.roles[role_id].definition
            for permission in sorted(role.permissions):
                pairs.append((role_id, permission))
        return pairs
