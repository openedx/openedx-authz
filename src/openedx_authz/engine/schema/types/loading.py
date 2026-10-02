"""Provenance and loading-output types for the authz schema pipeline.

:class:`SourceRecord` identifies where a schema contribution came from (ADR
0019), and :class:`SchemaDocument` is the per-file output of the ``load`` step
(ADR 0018). A loaded document carries the source that produced it, which is why
both live together here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from openedx_authz.engine.schema.types.definitions import (
    PermissionCategory,
    PermissionDefinition,
    RoleDefinition,
    RoleExtension,
)


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

        Combines the distribution with the module directory path and the file
        name, e.g. ``"openedx-authz:openedx_authz/authz/schema/roles.yaml"``.

        ``module`` is the dotted path of the owning directory and ``resource_path``
        is anchor-relative (so it may repeat the directory); only the file name
        is appended here to avoid duplicating the directory segments.
        """
        module_path = self.module.replace(".", "/")
        filename = self.resource_path.rsplit("/", 1)[-1]
        return f"{self.distribution}:{module_path}/{filename}"


@dataclass
class SchemaDocument:
    """One loaded ``.yaml`` schema file plus its provenance and priority.

    Output of the ``load`` step. Still per-file: cross-file references are not
    yet resolved (that happens during ``compile``).
    """

    source: SourceRecord
    priority: int
    categories: list[PermissionCategory] = field(default_factory=list)
    permissions: list[PermissionDefinition] = field(default_factory=list)
    roles: list[RoleDefinition] = field(default_factory=list)
    role_extensions: list[RoleExtension] = field(default_factory=list)
