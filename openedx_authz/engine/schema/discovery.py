"""Discover static authz schema resources (the ``discover`` step, ADR 0019).

Two contribution sources are merged, both expressed as
``(package_name, resource_path)`` pairs:

1. The ``authz.schema`` entry-point group. Each registered callable returns
   resource paths relative to its own module (e.g. openedx-authz's
   ``get_schema_resources``).
2. The ``OPENEDX_AUTHZ_SCHEMA_RESOURCES`` Django setting, a list of
   ``(package_name, resource_path)`` tuples. This is how the Tutor
   ``openedx-authz-schema`` patch and other operators contribute schema
   without shipping a package entry point.

Resource paths are resolved with ``importlib.resources`` so discovery does not
depend on virtualenv or container filesystem layout. If any provider raises,
discovery stops and reports the failing application (ADR 0019): deployment must
not proceed with an incomplete set of static definitions.

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
SETTINGS_RESOURCES_NAME = "OPENEDX_AUTHZ_SCHEMA_RESOURCES"

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DiscoveredResource:
    """A single located schema resource with enough info to build a source.

    Attributes:
        package: Importable package/module the resource lives in (the anchor
            passed to ``importlib.resources``).
        resource_path: Path to the resource within that package.
        origin: Where this contribution came from, ``"entry_point"``,
            ``"settings"``, or ``"explicit"`` (used for diagnostics).
    """

    package: str
    resource_path: str
    origin: str


class SchemaDiscoveryError(Exception):
    """Raised when a provider fails; names the failing contribution."""


class SchemaDiscovery:
    """Enumerates registered schema contributions into discovered resources."""

    def __init__(self, *, explicit_resources: list[tuple[str, str]] | None = None):
        """Initialize discovery.

        Args:
            explicit_resources: Optional ``(package, resource_path)`` pairs
                supplied directly (the ADR 0019 CI/local mode where explicit
                resources are passed to the command). Discovered in addition to
                entry points and settings.
        """
        self._explicit_resources = explicit_resources or []

    def discover(self) -> list[DiscoveredResource]:
        """Return every discovered resource in a deterministic order.

        Merges entry-point providers, the settings list, and any explicit
        resources, then de-duplicates and sorts. Order is normalized here
        because discovery order may vary across environments (ADR 0019);
        priority — not discovery order — drives conflict resolution later.

        Raises:
            SchemaDiscoveryError: If a provider callable raises or a declared
                resource cannot be located.
        """
        resources_found: list[DiscoveredResource] = []
        resources_found.extend(self._discover_entry_points())
        resources_found.extend(self._discover_settings_resources())
        resources_found.extend(
            DiscoveredResource(package=pkg, resource_path=path, origin="explicit")
            for pkg, path in self._explicit_resources
        )

        # De-duplicate on (package, resource_path) while keeping the first origin
        # seen, then sort for deterministic downstream processing.
        seen: dict[tuple[str, str], DiscoveredResource] = {}
        for resource in resources_found:
            key = (resource.package, resource.resource_path)
            seen.setdefault(key, resource)

        return sorted(seen.values(), key=lambda r: (r.package, r.resource_path))

    def _discover_entry_points(self) -> list[DiscoveredResource]:
        """Load the ``authz.schema`` group and call each provider.

        Uses ``importlib.metadata.entry_points`` to find providers and invokes
        each callable to get its resource paths, anchoring them to the module
        that owns the callable. Any provider exception is wrapped in
        :class:`SchemaDiscoveryError` identifying the entry-point name.
        """
        discovered: list[DiscoveredResource] = []
        for entry_point in metadata.entry_points(group=ENTRY_POINT_GROUP):
            try:
                provider = entry_point.load()
                paths = provider()
            except Exception as exc:  # noqa: BLE001 - re-raised with context below
                raise SchemaDiscoveryError(
                    f"authz.schema provider {entry_point.name!r} "
                    f"({entry_point.value}) failed during discovery: {exc}"
                ) from exc

            # The module that owns the callable is the resource anchor; the
            # provider returns paths relative to it.
            package = entry_point.module
            for path in paths:
                discovered.append(
                    DiscoveredResource(package=package, resource_path=path, origin="entry_point")
                )
        return discovered

    def _discover_settings_resources(self) -> list[DiscoveredResource]:
        """Read ``OPENEDX_AUTHZ_SCHEMA_RESOURCES`` from Django settings.

        Each item is a ``(package, resource_path)`` tuple. An absent, empty, or
        unconfigured setting yields no resources. Django is imported lazily so
        this module does not require a configured environment to import.
        """
        try:
            from django.conf import settings  # pylint: disable=import-outside-toplevel
        except ImportError:
            return []

        raw = getattr(settings, SETTINGS_RESOURCES_NAME, None) or []
        discovered: list[DiscoveredResource] = []
        for item in raw:
            try:
                package, resource_path = item
            except (ValueError, TypeError) as exc:
                raise SchemaDiscoveryError(
                    f"{SETTINGS_RESOURCES_NAME} entries must be (package, resource_path) "
                    f"tuples; got {item!r}."
                ) from exc
            discovered.append(
                DiscoveredResource(package=package, resource_path=resource_path, origin="settings")
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
