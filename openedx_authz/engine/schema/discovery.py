"""Discover static authz schema resources (the ``discover`` step, ADR 0019).

Providers register **directories** (not individual files); the loader reads
every ``.yaml`` file inside them. Two contribution sources are merged:

1. The ``authz.schema`` entry-point group. Each registered callable returns
   directory paths in the package-anchored format below (e.g.
   openedx-authz's ``["openedx_authz/authz/schema"]``).
2. The ``OPENEDX_AUTHZ_SCHEMA_DIRECTORIES`` Django setting, a list of directory
   path strings in the same format. This lets operators and CI contribute
   directories without shipping a package entry point.

Directory format: these are **not** filesystem paths (neither relative nor
absolute). Each is a package-anchored ``importlib.resources`` path: the first
segment is an importable top-level package (the *anchor*) and the remaining
forward-slash segments name a resource container within it. For example
``"openedx_authz/authz/schema"`` anchors on the ``openedx_authz`` package and
addresses its ``authz/schema`` subdirectory. Resolving through
``importlib.resources`` (rather than the filesystem) means discovery does not
depend on virtualenv or container layout, and works even when the package is
imported from a zip. If any provider raises, discovery
stops and reports the failing application (ADR 0019): deployment must not
proceed with an incomplete set of static definitions.

Timing: call only after Django settings are configured (from the management
command or ``AppConfig.ready()``). ``django.conf.settings`` is a lazy proxy, so
importing it is inert; the setting is only *read* at call time, inside
``_discover_settings_directories``. Reading before Django is configured raises
``ImproperlyConfigured``, which is caught and treated as "no contribution" so a
standalone CI schema check can run outside a Django process.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from importlib import metadata, resources

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

ENTRY_POINT_GROUP = "authz.schema"
SETTINGS_DIRECTORIES_NAME = "OPENEDX_AUTHZ_SCHEMA_DIRECTORIES"
SCHEMA_FILE_SUFFIXES = (".yaml", ".yml")

logger = logging.getLogger(__name__)


class Origin(StrEnum):
    """Diagnostic labels for where a discovered directory was contributed from.

    Members:
        ENTRY_POINT: Contributed via the ``authz.schema`` entry-point group.
        SETTINGS: Contributed via the ``OPENEDX_AUTHZ_SCHEMA_DIRECTORIES`` setting.
        PASSED_IN: Passed directly into ``SchemaDiscovery`` (CI/local mode).
    """

    ENTRY_POINT = "entry_point"
    SETTINGS = "settings"
    PASSED_IN = "passed_in"


@dataclass(frozen=True)
class DiscoveredResource:
    """A single located schema file discovered inside a contributed directory.

    Attributes:
        package: Importable top-level package used as the ``importlib.resources``
            anchor (e.g. ``openedx_authz``).
        resource_path: Path to the file within that anchor
            (e.g. ``authz/schema/course_roles.yaml``).
        module: Dotted path of the owning directory, used as the source-record
            module and provenance identity (e.g. ``openedx_authz.authz.schema``).
        origin: Which contribution route produced this resource, as an
            ``Origin`` member; diagnostics only.
    """

    package: str
    resource_path: str
    module: str
    origin: Origin

    def read_bytes(self) -> bytes:
        """Read this resource's bytes via ``importlib.resources``.

        Encapsulates the anchoring convention shared with directory discovery:
        a resource is a ``(package, resource_path)`` pair resolved as
        ``resources.files(package).joinpath(resource_path)``. Callers (the
        ``load`` step, ADR 0018) decide *when* to read; this keeps the *how*
        beside where the resource is produced.

        Raises:
            SchemaDiscoveryError: If the resource cannot be located or read.
        """
        try:
            return resources.files(self.package).joinpath(self.resource_path).read_bytes()
        except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
            raise SchemaDiscoveryError(
                f"Could not read schema resource {self.resource_path!r} from package {self.package!r}: {exc}"
            ) from exc


class SchemaDiscoveryError(Exception):
    """Raised when a provider fails or a declared directory cannot be read."""


class SchemaDiscovery:
    """Enumerates registered schema directories into discovered files."""

    def __init__(self, *, passed_in_directories: list[str] | None = None):
        """Initialize discovery.

        Args:
            passed_in_directories: Optional directory path strings supplied
                directly (the ADR 0019 CI/local mode where directories are
                passed to the command). Discovered in addition to entry points
                and settings.
        """
        self._passed_in_directories = passed_in_directories or []

    def discover(self) -> list[DiscoveredResource]:
        """Return every discovered schema file in a deterministic order.

        Expands entry-point directories, settings directories, and passed-in
        directories into individual ``.yaml`` files, then de-duplicates and
        sorts. Order is normalized here because discovery order may vary across
        environments (ADR 0019); priority — not discovery order — drives
        conflict resolution later.

        Sorting default: results are ordered by ``(package, resource_path)``
        ascending, so the same set of directories always yields the same list
        regardless of the order sources were discovered in.

        Raises:
            SchemaDiscoveryError: If a provider callable raises or a declared
                directory cannot be located/read.
        """
        found: list[DiscoveredResource] = []
        found.extend(self._discover_entry_points())
        found.extend(self._discover_settings_directories())
        for directory in self._passed_in_directories:
            found.extend(self._iter_directory(directory, origin=Origin.PASSED_IN))

        seen: dict[tuple[str, str], DiscoveredResource] = {}
        for resource in found:
            seen.setdefault((resource.package, resource.resource_path), resource)

        return sorted(seen.values(), key=lambda r: (r.package, r.resource_path))

    def _discover_entry_points(self) -> list[DiscoveredResource]:
        """Load the ``authz.schema`` group; each provider returns directories."""
        discovered: list[DiscoveredResource] = []
        for entry_point in metadata.entry_points(group=ENTRY_POINT_GROUP):
            try:
                provider = entry_point.load()
                directories = provider()
            except Exception as exc:  # noqa: BLE001 - re-raised with context below
                raise SchemaDiscoveryError(
                    f"authz.schema provider {entry_point.name!r} ({entry_point.value}) failed during discovery: {exc}"
                ) from exc
            for directory in directories:
                discovered.extend(self._iter_directory(directory, origin=Origin.ENTRY_POINT))
        return discovered

    def _discover_settings_directories(self) -> list[DiscoveredResource]:
        """Read ``OPENEDX_AUTHZ_SCHEMA_DIRECTORIES`` from Django settings.

        This is the operator/Tutor contribution route (ADR 0019 §1, ADR 0023 §4):
        each item is a directory path string. Absent, empty, or unconfigured
        settings yield nothing.

        The setting is read here (not at import), so if Django is installed but
        not configured the read raises ``ImproperlyConfigured``; that degrades
        to no contribution so a standalone CI schema check can run outside a
        Django process rather than failing with an unrelated Django error.
        """
        try:
            directories = getattr(settings, SETTINGS_DIRECTORIES_NAME, None) or []
        except ImproperlyConfigured:
            return []
        discovered: list[DiscoveredResource] = []
        for directory in directories:
            discovered.extend(self._iter_directory(directory, origin=Origin.SETTINGS))
        return discovered

    def _iter_directory(self, directory: str, *, origin: Origin) -> list[DiscoveredResource]:
        """Resolve a directory path and yield a resource per ``.yaml`` file.

        The path's first segment is an importable top-level package used as the
        anchor; the remainder is a subdirectory within it. For example
        ``"openedx_authz/authz/schema"`` anchors on ``openedx_authz`` and reads
        the ``authz/schema`` subdirectory.
        """
        parts = [segment for segment in directory.strip("/").split("/") if segment]
        if not parts:
            raise SchemaDiscoveryError(f"Empty schema directory path: {directory!r}.")

        anchor = parts[0]
        subpath = "/".join(parts[1:])
        module = ".".join(parts)

        try:
            base = resources.files(anchor)
            target = base.joinpath(subpath) if subpath else base
            entries = sorted(target.iterdir(), key=lambda entry: entry.name)
        except (FileNotFoundError, ModuleNotFoundError, NotADirectoryError, OSError) as exc:
            raise SchemaDiscoveryError(f"Could not read schema directory {directory!r}: {exc}") from exc

        discovered: list[DiscoveredResource] = []
        for entry in entries:
            if not entry.name.endswith(SCHEMA_FILE_SUFFIXES):
                continue
            if not entry.is_file():
                continue
            resource_path = f"{subpath}/{entry.name}" if subpath else entry.name
            discovered.append(
                DiscoveredResource(package=anchor, resource_path=resource_path, module=module, origin=origin)
            )
        return discovered
