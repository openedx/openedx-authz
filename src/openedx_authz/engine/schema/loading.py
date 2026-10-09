"""Read discovered resources into schema documents (the ``load`` step, ADR 0018).

Parses each ``.yaml`` schema resource into a :class:`SchemaDocument`, attaching
its :class:`SourceRecord` (including a content digest computed from the exact
bytes read). This step performs only parsing and structural shaping; semantic
checks belong to :mod:`.validation` and cross-file resolution to
:mod:`.compilation`.

No Casbin or Django imports, so it stays unit-testable in isolation.
"""

from __future__ import annotations

import hashlib
import logging
from importlib import metadata

import yaml

from openedx_authz.engine.schema.discovery import DiscoveredResource
from openedx_authz.engine.schema.exceptions import SchemaLoadError
from openedx_authz.engine.schema.types import (
    PermissionCategory,
    PermissionDefinition,
    RoleDefinition,
    RoleExtension,
    SchemaDocument,
    SourceRecord,
)

logger = logging.getLogger(__name__)


class SchemaLoader:
    """Turns discovered resources into typed schema documents.

    Reading a resource's bytes is the ``load`` step's responsibility (ADR 0018):
    each :class:`DiscoveredResource` knows how to read itself, so the loader
    controls *when* files are read and computes the content digest from the
    exact bytes it parses.
    """

    _UNKNOWN_DISTRIBUTION = "unknown"
    _distribution_ambiguity_warned: set[tuple[str, str, str]] = set()

    def load(self, resources: list[DiscoveredResource]) -> list[SchemaDocument]:
        """Load every discovered resource into a :class:`SchemaDocument`.

        Raises:
            SchemaLoadError: On invalid YAML or an unusable document structure.
        """
        documents: list[SchemaDocument] = []
        for resource in resources:
            contents = resource.read_bytes()
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
            raise SchemaLoadError(f"Invalid YAML in {resource.package}:{resource.resource_path}: {exc}") from exc

        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise SchemaLoadError(
                f"Schema file {resource.package}:{resource.resource_path} must be a mapping "
                f"at the top level, got {type(data).__name__}."
            )
        return data

    def _build_source_record(self, resource: DiscoveredResource, contents: bytes, schema_version: str) -> SourceRecord:
        """Assemble packaging metadata + content digest into a SourceRecord.

        Resolves the installed distribution name/version that owns the resource
        package via ``importlib.metadata`` and hashes ``contents`` for the
        digest. Falls back to ``"unknown"`` when the package is not tied to an
        installed distribution (e.g. operator-supplied settings resources).
        """
        distribution, version = self._resolve_distribution(resource)
        content_digest = hashlib.sha256(contents).hexdigest()
        return SourceRecord(
            distribution=distribution,
            distribution_version=version,
            module=resource.module,
            resource_path=resource.resource_path,
            schema_version=schema_version,
            content_digest=content_digest,
        )

    @classmethod
    def _resolve_distribution(cls, resource: DiscoveredResource) -> tuple[str, str]:
        """Map a discovered resource to its providing distribution name and version.

        A top-level import package can be provided by more than one installed
        distribution (namespace packages, overlapping/legacy installs), so
        ``packages_distributions()`` returns a *list* of candidate names. The
        same source must resolve to the same distribution under every deployment
        layout (ADR 0019 §2), so an arbitrary ``candidates[0]`` is not good
        enough: when several distributions claim the top-level package we pick
        the one that actually ships this resource's file, and only fall back to
        a deterministic (sorted) choice when no single owner can be identified.
        """
        top_level = resource.package.split(".", 1)[0]
        try:
            mapping = metadata.packages_distributions()
        # pylint: disable=broad-exception-caught
        except Exception:  # noqa: BLE001 - defensive; metadata quirks across envs
            mapping = {}
        candidates = mapping.get(top_level) or []
        if not candidates:
            return top_level, cls._UNKNOWN_DISTRIBUTION

        distribution = cls._select_owning_distribution(candidates, resource)
        try:
            return distribution, metadata.version(distribution)
        except metadata.PackageNotFoundError:
            return distribution, cls._UNKNOWN_DISTRIBUTION

    @classmethod
    def _select_owning_distribution(cls, candidates: list[str], resource: DiscoveredResource) -> str:
        """Choose the distribution that ships ``resource`` from the candidate list.

        With a single candidate there is nothing to disambiguate. With several,
        we match each distribution's recorded file list against the resource's
        installed path (``package/resource_path``) and return the one that owns
        it. If exactly zero or more than one distribution claims the file (or the
        file lists are unavailable), we cannot know the true owner, so we return
        the first candidate in sorted order — a stable choice across environments
        — and log the ambiguity once per distinct (top_level, resource_path, selected)
        combination.
        """
        if len(candidates) == 1:
            return candidates[0]

        installed_path = f"{resource.package}/{resource.resource_path}"
        owners = [name for name in candidates if cls._distribution_ships(name, installed_path)]
        if len(owners) == 1:
            return owners[0]

        fallback = sorted(candidates)[0]
        # Deduplicate warnings by tracking (top_level, resource_path, selected) combinations
        warn_key = (resource.package, resource.resource_path, fallback)
        if warn_key not in cls._distribution_ambiguity_warned:
            cls._distribution_ambiguity_warned.add(warn_key)
            logger.info(
                "Schema resource for package '%s' is claimed by multiple distributions %s; "
                "deterministically selected '%s'.",
                resource.package,
                sorted(candidates),
                fallback,
                extra={
                    "top_level": resource.package,
                    "resource_path": resource.resource_path,
                    "candidates": sorted(candidates),
                    "matched_owners": sorted(owners),
                    "selected": fallback,
                },
            )
        return fallback

    @staticmethod
    def _distribution_ships(distribution: str, installed_path: str) -> bool:
        """Return whether ``distribution`` records a file matching ``installed_path``.

        ``Distribution.files`` lists the files the distribution installed, as
        anchor-relative ``PackagePath`` values (e.g.
        ``openedx_authz/authz/schema/course_roles.yaml``). A resource belongs to
        the distribution when one of those paths ends with the resource's
        ``package/resource_path``. Metadata gaps (``files`` is ``None`` or the
        distribution is missing) mean "cannot confirm ownership", not an error.
        """
        try:
            files = metadata.distribution(distribution).files or []
        except metadata.PackageNotFoundError:
            return False
        return any(str(path).endswith(installed_path) for path in files)

    def _build_document(self, raw: dict, source: SourceRecord) -> SchemaDocument:
        """Map the parsed mapping's blocks into a typed SchemaDocument.

        ``priority`` is a *required* field per ``authz-schema-v1.json``; a higher
        value wins when contributions conflict (see
        ``docs/references/authorization-schema.rst``). Enforcing that it is
        present is the ``validate`` step's job, not this one — the loader only
        parses and shapes (ADR 0018), and it defers required-field enforcement
        to validation exactly as it does for ``schema_version``. So a missing
        ``priority`` is read as ``0`` (the lowest precedence) here and rejected
        later by validation, whereas a *malformed* (non-integer) ``priority`` is
        raised now because it cannot be parsed at all.
        """
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
        """Build a ``PermissionCategory`` from one ``permission_categories`` entry."""
        self._require_mapping(item, "permission_categories", source)
        return PermissionCategory(
            id=item.get("id", ""),
            display_name=item.get("display_name", ""),
            description=item.get("description", ""),
            icon=item.get("icon"),
        )

    def _build_permission(self, item: dict, source: SourceRecord) -> PermissionDefinition:
        """Build a ``PermissionDefinition`` from one ``permissions`` entry."""
        self._require_mapping(item, "permissions", source)
        return PermissionDefinition(
            namespace=item.get("namespace", ""),
            name=item.get("name", ""),
            display_name=item.get("display_name", ""),
            description=item.get("description", ""),
            category_id=item.get("category_id", ""),
            scopes=self._as_tuple(item.get("scopes")),
            icon=item.get("icon"),
        )

    def _build_role(self, item: dict, source: SourceRecord) -> RoleDefinition:
        """Build a ``RoleDefinition`` from one ``roles`` entry."""
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
        """Build a ``RoleExtension`` from one ``role_extensions`` entry.

        ``hidden`` is read as tri-state: absent stays ``None`` ("leave
        unchanged"), distinct from an explicit ``False`` (ADR 0023 §1).
        """
        self._require_mapping(item, "role_extensions", source)
        return RoleExtension(
            role_id=item.get("role_id", ""),
            add_permissions=self._as_tuple(item.get("add_permissions")),
            remove_permissions=self._as_tuple(item.get("remove_permissions")),
            display_name=item.get("display_name"),
            description=item.get("description"),
            icon=item.get("icon"),
            hidden=item.get("hidden"),  # tri-state: None means "leave unchanged"
        )

    @staticmethod
    def _require_mapping(item, block: str, source: SourceRecord) -> None:
        """Raise ``SchemaLoadError`` (naming the block and source) if ``item`` is not a mapping."""
        if not isinstance(item, dict):
            raise SchemaLoadError(
                f"{source.source_id}: each entry in '{block}' must be a mapping, got {type(item).__name__}."
            )
