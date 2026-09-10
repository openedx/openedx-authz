"""Read discovered resources into schema documents (the ``load`` step, ADR 0018).

Parses each ``.authz.yaml`` resource into a :class:`SchemaDocument`, attaching
its :class:`SourceRecord` (including a content digest computed from the exact
bytes read). This step performs only parsing and structural shaping; semantic
checks belong to :mod:`.validation` and cross-file resolution to
:mod:`.compilation`.

No Casbin or Django imports, so it stays unit-testable in isolation.
"""

from __future__ import annotations

import hashlib
from importlib import metadata

import yaml

from openedx_authz.engine.schema.discovery import DiscoveredResource, SchemaDiscovery
from openedx_authz.engine.schema.exceptions import SchemaLoadError
from openedx_authz.engine.schema.types import (
    PermissionCategory,
    PermissionDefinition,
    RoleDefinition,
    RoleExtension,
    SchemaDocument,
    SourceRecord,
)

UNKNOWN = "unknown"


class SchemaLoader:
    """Turns discovered resources into typed schema documents."""

    def __init__(self, discovery: SchemaDiscovery | None = None):
        """Args:
        discovery: Discovery instance used to read resource bytes. Injected
            for testability; defaults to a standard :class:`SchemaDiscovery`.
        """
        self._discovery = discovery or SchemaDiscovery()

    def load(self, resources: list[DiscoveredResource]) -> list[SchemaDocument]:
        """Load every discovered resource into a :class:`SchemaDocument`.

        Raises:
            SchemaLoadError: On invalid YAML or an unusable document structure.
        """
        documents: list[SchemaDocument] = []
        for resource in resources:
            contents = self._discovery.resolve_contents(resource)
            raw = self._parse_yaml(contents, resource)
            schema_version = str(raw.get("schema_version", ""))
            source = self._build_source_record(resource, contents, schema_version)
            documents.append(self._build_document(raw, source))
        return documents

    def _parse_yaml(self, contents: bytes, resource: DiscoveredResource) -> dict:
        """Parse YAML bytes into a mapping, raising on malformed input."""
        try:
            data = yaml.safe_load(contents)
        except yaml.YAMLError as exc:
            raise SchemaLoadError(
                f"Invalid YAML in {resource.package}:{resource.resource_path}: {exc}"
            ) from exc

        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise SchemaLoadError(
                f"Schema file {resource.package}:{resource.resource_path} must be a mapping "
                f"at the top level, got {type(data).__name__}."
            )
        return data

    def _build_source_record(
        self, resource: DiscoveredResource, contents: bytes, schema_version: str
    ) -> SourceRecord:
        """Assemble packaging metadata + content digest into a SourceRecord.

        Resolves the installed distribution name/version that owns the resource
        package via ``importlib.metadata`` and hashes ``contents`` for the
        digest. Falls back to ``"unknown"`` when the package is not tied to an
        installed distribution (e.g. operator-supplied settings resources).
        """
        distribution, version = self._resolve_distribution(resource.package)
        content_digest = hashlib.sha256(contents).hexdigest()
        return SourceRecord(
            distribution=distribution,
            distribution_version=version,
            module=resource.package,
            resource_path=resource.resource_path,
            schema_version=schema_version,
            content_digest=content_digest,
        )

    @staticmethod
    def _resolve_distribution(package: str) -> tuple[str, str]:
        """Map an import package to its providing distribution name and version."""
        top_level = package.split(".", 1)[0]
        try:
            mapping = metadata.packages_distributions()
        # pylint: disable=broad-exception-caught
        except Exception:  # noqa: BLE001 - defensive; metadata quirks across envs
            mapping = {}
        candidates = mapping.get(top_level) or []
        if candidates:
            distribution = candidates[0]
            try:
                return distribution, metadata.version(distribution)
            except metadata.PackageNotFoundError:
                return distribution, UNKNOWN
        return top_level, UNKNOWN

    def _build_document(self, raw: dict, source: SourceRecord) -> SchemaDocument:
        """Map the parsed mapping's blocks into a typed SchemaDocument."""
        try:
            priority = int(raw.get("priority", 0))
        except (TypeError, ValueError) as exc:
            raise SchemaLoadError(
                f"{source.source_id}: 'priority' must be an integer, got {raw.get('priority')!r}."
            ) from exc

        return SchemaDocument(
            source=source,
            priority=priority,
            categories=[self._build_category(item, source) for item in raw.get("permission_categories", []) or []],
            permissions=[self._build_permission(item, source) for item in raw.get("permissions", []) or []],
            roles=[self._build_role(item, source) for item in raw.get("roles", []) or []],
            role_extensions=[self._build_extension(item, source) for item in raw.get("role_extensions", []) or []],
        )

    @staticmethod
    def _as_tuple(value) -> tuple[str, ...]:
        """Coerce a YAML list (or None) into a tuple of strings."""
        if not value:
            return ()
        if isinstance(value, str):
            return (value,)
        return tuple(str(item) for item in value)

    def _build_category(self, item: dict, source: SourceRecord) -> PermissionCategory:
        self._require_mapping(item, "permission_categories", source)
        return PermissionCategory(
            id=item.get("id", ""),
            display_name=item.get("display_name", ""),
            description=item.get("description", ""),
            icon=item.get("icon"),
        )

    def _build_permission(self, item: dict, source: SourceRecord) -> PermissionDefinition:
        self._require_mapping(item, "permissions", source)
        return PermissionDefinition(
            namespace=item.get("namespace", ""),
            name=item.get("name", ""),
            display_name=item.get("display_name", ""),
            description=item.get("description", ""),
            category=item.get("category", ""),
            scopes=self._as_tuple(item.get("scopes")),
            icon=item.get("icon"),
        )

    def _build_role(self, item: dict, source: SourceRecord) -> RoleDefinition:
        self._require_mapping(item, "roles", source)
        return RoleDefinition(
            id=item.get("id", ""),
            display_name=item.get("display_name", ""),
            description=item.get("description", ""),
            scopes=self._as_tuple(item.get("scopes")),
            permissions=self._as_tuple(item.get("permissions")),
            icon=item.get("icon"),
            hidden=bool(item.get("hidden", False)),
        )

    def _build_extension(self, item: dict, source: SourceRecord) -> RoleExtension:
        self._require_mapping(item, "role_extensions", source)
        return RoleExtension(
            role=item.get("role", ""),
            add_permissions=self._as_tuple(item.get("add_permissions")),
            remove_permissions=self._as_tuple(item.get("remove_permissions")),
            display_name=item.get("display_name"),
            description=item.get("description"),
            icon=item.get("icon"),
            hidden=item.get("hidden"),  # tri-state: None means "leave unchanged"
        )

    @staticmethod
    def _require_mapping(item, block: str, source: SourceRecord) -> None:
        if not isinstance(item, dict):
            raise SchemaLoadError(
                f"{source.source_id}: each entry in '{block}' must be a mapping, got {type(item).__name__}."
            )
