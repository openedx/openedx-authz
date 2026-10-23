"""Read discovered resources into parsed documents (the ``parse`` step, ADR 0018).

Parses each YAML schema resource without imposing authorization-schema
structure, attaching its :class:`SourceRecord` with a content digest computed
from the exact bytes read. JSON Schema validation owns structural requirements,
typed shaping belongs to :mod:`.loading`, and semantic checks belong to
:mod:`.validation`.

No Casbin or Django imports, so parsing stays unit-testable in isolation.
"""

from __future__ import annotations

import hashlib
import logging
from importlib import metadata

import yaml

from openedx_authz.engine.schema.discovery import (
    SETTINGS_FILE_VERSION,
    DiscoveredFileResource,
    DiscoveredResource,
)
from openedx_authz.engine.schema.exceptions import SchemaLoadError
from openedx_authz.engine.schema.types import ParsedSchemaDocument, SourceFileRecord, SourceRecord

logger = logging.getLogger(__name__)

UNKNOWN_DISTRIBUTION = "unknown"


class SchemaParser:
    """Read discovered resources into untyped YAML values with provenance.

    Each :class:`DiscoveredResource` knows how to read itself, so the parser
    controls when files are read and computes the content digest from the exact
    bytes passed to the YAML parser.
    """

    distribution_ambiguity_warned: set[tuple[str, str, str]] = set()
    """Tracks warned (package, resource_path, selected) combinations to deduplicate logs."""

    def parse(self, resources: list[DiscoveredResource]) -> list[ParsedSchemaDocument]:
        """Parse every resource without imposing authorization-schema structure."""
        documents = []
        for resource in resources:
            contents = resource.read_bytes()
            for data in self.parse_yamls(contents, resource):
                schema_version = str(data.get("schema_version", "")) if isinstance(data, dict) else ""
                source = self.build_source_record(resource, contents, schema_version)
                documents.append(ParsedSchemaDocument(source=source, data=data))
        return documents

    @staticmethod
    def parse_yamls(contents: bytes, resource: DiscoveredResource) -> list[object]:
        """Parse YAML bytes as a multi-document stream
        Skipping empty documents, and preserve the resulting root value.
        """
        try:
            return [doc for doc in yaml.safe_load_all(contents) if doc is not None]
        except yaml.YAMLError as exc:
            raise SchemaLoadError(f"Invalid YAML in {resource.package}:{resource.resource_path}: {exc}") from exc

    def build_source_record(self, resource: DiscoveredResource, contents: bytes, schema_version: str) -> SourceRecord:
        """Assemble packaging metadata and a digest into a SourceRecord.

        Resolves the installed distribution name/version that owns the resource
        package via ``importlib.metadata`` and hashes ``contents`` for the
        digest. Falls back to ``"unknown"`` when the package is not tied to an
        installed distribution (e.g. operator-supplied settings resources).
        """
        distribution, version = self.resolve_distribution(resource)
        content_digest = hashlib.sha256(contents).hexdigest()
        source_record = {
            'distribution': distribution,
            'distribution_version': version,
            'module': resource.module,
            'resource_path': resource.resource_path,
            'schema_version': schema_version,
            'content_digest': content_digest,
        }
        if isinstance(resource, DiscoveredFileResource):
            return SourceFileRecord(**source_record)
        return SourceRecord(**source_record)

    @classmethod
    def resolve_distribution(cls, resource: DiscoveredResource) -> tuple[str, str]:
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
        if isinstance(resource, DiscoveredFileResource):
            return resource.package, SETTINGS_FILE_VERSION
        top_level = resource.package.split(".", 1)[0]
        try:
            mapping = metadata.packages_distributions()
        except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - defensive; metadata quirks across envs
            mapping = {}
        # ``packages_distributions()`` can list the same distribution more than
        # once for one top-level package (observed with editable installs and
        # overlapping metadata). Those are not competing owners, so collapse to
        # the distinct names before resolving; otherwise a lone real owner that
        # happens to be listed twice looks "ambiguous" and the fallback path
        # warns on every resource for a non-problem.
        candidates = sorted(set(mapping.get(top_level) or []))
        if not candidates:
            return top_level, UNKNOWN_DISTRIBUTION

        distribution = cls.select_owning_distribution(candidates, resource)
        try:
            return distribution, metadata.version(distribution)
        except metadata.PackageNotFoundError:
            return distribution, UNKNOWN_DISTRIBUTION

    @classmethod
    def select_owning_distribution(cls, candidates: list[str], resource: DiscoveredResource) -> str:
        """Choose the distribution that ships ``resource`` from the candidate list.

        With a single candidate there is nothing to disambiguate. With several,
        we match each distribution's recorded file list against the resource's
        installed path (``package/resource_path``) and return the one that owns
        it. If exactly zero or more than one distribution claims the file (or the
        file lists are unavailable), we cannot know the true owner, so we return
        the first candidate in sorted order, a stable choice across environments,
        and log the ambiguity once per distinct (package, resource_path, selected)
        combination.
        """
        if len(candidates) == 1:
            return candidates[0]

        installed_path = f"{resource.package}/{resource.resource_path}"
        owners = [name for name in candidates if cls.distribution_ships(name, installed_path)]
        if len(owners) == 1:
            return owners[0]

        fallback = sorted(candidates)[0]
        # Deduplicate warnings by tracking (package, resource_path, selected) combinations.
        warn_key = (resource.package, resource.resource_path, fallback)
        if warn_key not in cls.distribution_ambiguity_warned:
            cls.distribution_ambiguity_warned.add(warn_key)
            logger.info(
                "Schema resource for package '%s' is claimed by multiple distributions %s; "
                "deterministically selected '%s'.",
                resource.package,
                sorted(candidates),
                fallback,
                extra={
                    "package": resource.package,
                    "resource_path": resource.resource_path,
                    "candidates": sorted(candidates),
                    "matched_owners": sorted(owners),
                    "selected": fallback,
                },
            )
        return fallback

    @staticmethod
    def distribution_ships(distribution: str, installed_path: str) -> bool:
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
