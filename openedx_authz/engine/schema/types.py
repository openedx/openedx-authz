"""Typed schema objects and source records for the authz schema pipeline.

These dataclasses are the data contract passed between lifecycle steps
(ADR 0018): discovery produces :class:`DiscoveredResource`, loading produces
:class:`SchemaDocument`, and compilation produces :class:`CompiledSchema`.

Definition field shapes follow ``docs/references/authorization-schema.rst``
(reference PR): identifiers match ``[a-z][a-z0-9_]*``, permission IDs join
``namespace`` and ``name`` with a period, and the internal Casbin forms
(``act^...``, ``role^...``) never appear here.

This module is intentionally free of any Casbin or Django imports so it can be
unit-tested in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceRecord:
    """Identifies a single schema contribution across deployment layouts.

    Per ADR 0019 §2, these packaging-based values (not filesystem paths) must
    identify the same source under Tutor, native, and local deployments. A
    compiled definition retains every ``SourceRecord`` that contributed to it,
    so a role assembled from a base definition plus one or more extensions
    keeps all of its sources.

    Attributes:
        distribution: Installed distribution name, e.g. ``"openedx-authz"``.
        distribution_version: Version of that distribution.
        module: Python module that owns the resource.
        resource_path: Resource path within that module.
        schema_version: The ``schema_version`` declared by the file.
        content_digest: Digest of the resource contents (change detection).
    """

    distribution: str
    distribution_version: str
    module: str
    resource_path: str
    schema_version: str
    content_digest: str

    @property
    def source_id(self) -> str:
        """Stable, human-readable id.

        Combines the distribution with the module path and resource path, e.g.
        ``"openedx-authz:openedx_authz/authz/course_roles.authz.yaml"``.
        """
        module_path = self.module.replace(".", "/")
        return f"{self.distribution}:{module_path}/{self.resource_path}"


# ---------------------------------------------------------------------------
# Definition objects (ADR 0017 / reference)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PermissionCategory:
    """A display/grouping category for permissions. Grants no access."""

    id: str
    display_name: str
    description: str
    icon: str | None = None


@dataclass(frozen=True)
class PermissionDefinition:
    """A single permission.

    The complete permission ID (used by role definitions, extensions, app
    checks, and API responses) is :attr:`identifier`.
    """

    namespace: str
    name: str
    display_name: str
    description: str
    category: str
    scopes: tuple[str, ...]
    icon: str | None = None

    @property
    def identifier(self) -> str:
        """Complete permission ID, e.g. ``"courses.view_course"``."""
        return f"{self.namespace}.{self.name}"


@dataclass(frozen=True)
class RoleDefinition:
    """A static role listing every permission assigned to it.

    ``hidden`` mirrors ADR 0023: a hidden role is excluded from normal role
    discovery/selection but keeps its assignments, permission checks, and
    reserved ID.
    """

    id: str
    display_name: str
    description: str
    scopes: tuple[str, ...]
    permissions: tuple[str, ...]
    icon: str | None = None
    hidden: bool = False


@dataclass(frozen=True)
class RoleExtension:
    """A change to an existing static role (ADR 0023).

    Only the included fields change; ``None``/empty means "leave unchanged".
    An extension can never change the role ID or replace the whole definition.
    ``hidden`` is tri-state: ``None`` leaves the current value untouched.
    """

    role: str
    add_permissions: tuple[str, ...] = ()
    remove_permissions: tuple[str, ...] = ()
    display_name: str | None = None
    description: str | None = None
    icon: str | None = None
    hidden: bool | None = None


# ---------------------------------------------------------------------------
# Loading output
# ---------------------------------------------------------------------------


@dataclass
class SchemaDocument:
    """One loaded ``.authz.yaml`` file plus its provenance and priority.

    Output of the ``load`` step. Still per-file: cross-file references are not
    yet resolved (that happens during ``compile``).
    """

    source: SourceRecord
    priority: int
    categories: list[PermissionCategory] = field(default_factory=list)
    permissions: list[PermissionDefinition] = field(default_factory=list)
    roles: list[RoleDefinition] = field(default_factory=list)
    role_extensions: list[RoleExtension] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Compilation output
# ---------------------------------------------------------------------------


# Origin of a contribution to a role or a role-permission grant (ADR 0023/0024).
ORIGIN_BASE = "base"
ORIGIN_EXTENSION = "extension"


@dataclass(frozen=True)
class RelationshipSource:
    """Provenance of a single role-permission grant (ADR 0024).

    Attributes:
        source: The contributing source record.
        origin_kind: ``ORIGIN_BASE`` (from the role's own definition) or
            ``ORIGIN_EXTENSION`` (added by a ``role_extensions`` entry).
        priority: The contributing file's priority.
    """

    source: SourceRecord
    origin_kind: str
    priority: int


@dataclass(frozen=True)
class CompiledDefinition:
    """A resolved definition plus every source that contributed to it.

    Attributes:
        kind: ``"category"`` | ``"permission"`` | ``"role"``.
        key: The category id, permission identifier, or role id.
        definition: The resolved dataclass instance (category/permission/role).
        sources: All contributing sources, in priority-then-discovery order.
    """

    kind: str
    key: str
    definition: object
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
    # Populated by the compiler; consumed when persisting sources (ADR 0024).
    role_permission_sources: dict[tuple[str, str], list[RelationshipSource]] = field(default_factory=dict)

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
