"""Discover static authz schema resources (the ``discover`` step, ADR 0019).

Providers register **directories** (not individual files); the loader reads
every ``.yaml`` file inside them. Two contribution sources are merged:

1. The ``authz.schema`` entry-point group. Each registered callable returns
   directory paths relative to an importable top-level package (e.g.
   openedx-authz's ``["openedx_authz/authz/schema"]``).
2. The ``OPENEDX_AUTHZ_SCHEMA_DIRECTORIES`` Django setting, a list of directory
   path strings in the same format. This lets operators and CI contribute
   directories without shipping a package entry point.

Directory paths are resolved with ``importlib.resources`` so discovery does not
depend on virtualenv or container layout. If any provider raises, discovery
stops and reports the failing application (ADR 0019): deployment must not
proceed with an incomplete set of static definitions.

Timing: call only after Django settings are available (from the management
command or ``AppConfig.ready()``), never at module import. Django is imported
lazily so this module stays importable (and unit-testable) without a configured
Django environment.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from importlib import metadata, resources

ENTRY_POINT_GROUP = "authz.schema"
SETTINGS_DIRECTORIES_NAME = "OPENEDX_AUTHZ_SCHEMA_DIRECTORIES"
SCHEMA_FILE_SUFFIXES = (".yaml", ".yml")

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DiscoveredResource:
    """A single located schema file discovered inside a contributed directory.

    Attributes:
        package: Importable top-level package used as the ``importlib.resources``
            anchor (e.g. ``openedx_authz``).
        resource_path: Path to the file within that anchor
            (e.g. ``authz/schema/course_roles.authz.yaml``).
        module: Dotted path of the owning directory, used as the source-record
            module and provenance identity (e.g. ``openedx_authz.authz.schema``).
        origin: Where the contribution came from: ``"entry_point"``,
            ``"settings"``, or ``"explicit"`` (diagnostics only).
    """

    package: str
    resource_path: str
    module: str
    origin: str


class SchemaDiscoveryError(Exception):
    """Raised when a provider fails or a declared directory cannot be read."""


class SchemaDiscovery:
    """Enumerates registered schema directories into discovered files."""

    def __init__(self, *, explicit_directories: list[str] | None = None):
        """Initialize discovery.

        Args:
            explicit_directories: Optional directory path strings supplied
                directly (the ADR 0019 CI/local mode where directories are
                passed to the command). Discovered in addition to entry points
                and settings.
        """
        self._explicit_directories = explicit_directories or []

    def discover(self) -> list[DiscoveredResource]:
        """Return every discovered schema file in a deterministic order.

        Expands entry-point directories, settings directories, and explicit
        directories into individual ``.yaml`` files, then de-duplicates and
        sorts. Order is normalized here because discovery order may vary across
        environments (ADR 0019); priority — not discovery order — drives
        conflict resolution later.

        Raises:
            SchemaDiscoveryError: If a provider callable raises or a declared
                directory cannot be located/read.
        """
        found: list[DiscoveredResource] = []
        found.extend(self._discover_entry_points())
        found.extend(self._discover_settings_directories())
        for directory in self._explicit_directories:
            found.extend(self._iter_directory(directory, origin="explicit"))

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
                    f"authz.schema provider {entry_point.name!r} "
                    f"({entry_point.value}) failed during discovery: {exc}"
                ) from exc
            for directory in directories:
                discovered.extend(self._iter_directory(directory, origin="entry_point"))
        return discovered

    def _discover_settings_directories(self) -> list[DiscoveredResource]:
        """Read ``OPENEDX_AUTHZ_SCHEMA_DIRECTORIES`` from Django settings.

        Each item is a directory path string. Absent/empty/unconfigured setting
        yields nothing. Django is imported lazily.
        """
        try:
            from django.conf import settings  # pylint: disable=import-outside-toplevel
        except ImportError:
            return []

        directories = getattr(settings, SETTINGS_DIRECTORIES_NAME, None) or []
        discovered: list[DiscoveredResource] = []
        for directory in directories:
            discovered.extend(self._iter_directory(directory, origin="settings"))
        return discovered

    def _iter_directory(self, directory: str, *, origin: str) -> list[DiscoveredResource]:
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
            raise SchemaDiscoveryError(
                f"Could not read schema directory {directory!r}: {exc}"
            ) from exc

        discovered: list[DiscoveredResource] = []
        for entry in entries:
            if not entry.name.endswith(SCHEMA_FILE_SUFFIXES):
                continue
            if not entry.is_file():
                continue
            resource_path = f"{subpath}/{entry.name}" if subpath else entry.name
            discovered.append(
                DiscoveredResource(
                    package=anchor, resource_path=resource_path, module=module, origin=origin
                )
            )
        return discovered

    def resolve_contents(self, resource: DiscoveredResource) -> bytes:
        """Read a discovered resource's bytes via ``importlib.resources``.

        Kept separate from :meth:`discover` so the loader controls when files
        are read and so the content digest is computed from the exact bytes
        used.

        Raises:
            SchemaDiscoveryError: If the resource cannot be located or read.
        """
        try:
            return resources.files(resource.package).joinpath(resource.resource_path).read_bytes()
        except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
            raise SchemaDiscoveryError(
                f"Could not read schema resource {resource.resource_path!r} "
                f"from package {resource.package!r}: {exc}"
            ) from exc
