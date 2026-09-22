#!/usr/bin/env python
"""Regenerate the vendored Paragon icon-name allow-list.

ADR 0017 §4 requires schema validation to reject ``icon`` values that are not
valid ``@openedx/paragon/icons`` names. There is no Python-side source of truth
for that name set, so we vendor it: this script fetches the published Paragon
icon export barrel and writes it as a frozenset in
``openedx_authz/engine/schema/paragon_icons.py``.

Why a vendored list instead of a runtime lookup: ``openedx-authz`` is a Python
backend with no Node/Paragon dependency, so the JS package is not importable at
validation time. Pinning a version keeps validation deterministic and lets the
list follow Paragon's own deprecation process when an icon is renamed or removed
(ADR 0017 §4).

The Paragon version is pinned to match the ``@openedx/paragon`` major used by
``frontend-app-admin-console`` (``^23``). Bump :data:`PARAGON_VERSION` and rerun
``make paragon_icons`` to refresh.

Usage::

    make paragon_icons
    python scripts/generate_paragon_icons.py            # same thing
    python scripts/generate_paragon_icons.py --version 23.21.3 --check

``--check`` regenerates into memory and fails (exit 1) if the committed file is
stale, without writing. Intended for CI.
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Pinned to the @openedx/paragon major used by frontend-app-admin-console master
# (peerDependency "@openedx/paragon": "^23"). This is the concrete 23.x release
# the vendored list is generated from.
PARAGON_VERSION = "23.21.3"

# The published package re-exports every generated icon component from this
# built barrel as ``export { default as <IconName> } from "./<file>";``.
ICONS_BARREL_URL = "https://unpkg.com/@openedx/paragon@{version}/icons/es5/index.js"

# Captures the exported component name in ``export { default as Name } from ...``.
EXPORT_RE = re.compile(r"export\s*\{\s*default\s+as\s+([A-Za-z_$][\w$]*)\s*\}")

# Where the vendored module lives, relative to the repo root.
OUTPUT_PATH = Path("openedx_authz/engine/schema/paragon_icons.py")

FILE_TEMPLATE = '''\
"""Vendored allow-list of valid ``@openedx/paragon/icons`` names.

GENERATED FILE -- do not edit by hand. Regenerate with::

    make paragon_icons

The names are the component exports of ``@openedx/paragon/icons`` at the pinned
version below, used by :mod:`openedx_authz.engine.schema.validation` to reject
schema ``icon`` values that are not real Paragon icons (ADR 0017 §4).

Source: {source_url}
Paragon version: {version}
Icon count: {count}
"""

from __future__ import annotations

PARAGON_VERSION = "{version}"

PARAGON_ICON_NAMES: frozenset[str] = frozenset(
    {{
{entries}
    }}
)
'''


class GenerationError(RuntimeError):
    """Raised when the icon list cannot be fetched or parsed."""


def fetch_barrel(version: str) -> str:
    """Return the text of the Paragon icons export barrel for ``version``."""
    url = ICONS_BARREL_URL.format(version=version)
    try:
        with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 - fixed https host
            return response.read().decode("utf-8")
    except urllib.error.URLError as exc:
        raise GenerationError(f"Could not fetch Paragon icons from {url}: {exc}") from exc


def parse_icon_names(barrel: str) -> list[str]:
    """Extract the sorted, de-duplicated icon names from the export barrel."""
    names = sorted(set(EXPORT_RE.findall(barrel)))
    if not names:
        raise GenerationError("No icon exports found; the barrel format may have changed.")
    return names


def render_module(names: list[str], version: str) -> str:
    """Render the vendored Python module source for the given icon names."""
    entries = "\n".join(f'        "{name}",' for name in names)
    return FILE_TEMPLATE.format(
        source_url=ICONS_BARREL_URL.format(version=version),
        version=version,
        count=len(names),
        entries=entries,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version",
        default=PARAGON_VERSION,
        help=f"Paragon version to generate from (default: {PARAGON_VERSION}).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if the committed file is out of date instead of writing it.",
    )
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parent.parent
    output_path = repo_root / OUTPUT_PATH

    try:
        names = parse_icon_names(fetch_barrel(args.version))
    except GenerationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    rendered = render_module(names, args.version)

    if args.check:
        current = output_path.read_text(encoding="utf-8") if output_path.exists() else ""
        if current != rendered:
            print(
                f"error: {OUTPUT_PATH} is out of date; run 'make paragon_icons'.",
                file=sys.stderr,
            )
            return 1
        print(f"{OUTPUT_PATH} is up to date ({len(names)} icons).")
        return 0

    output_path.write_text(rendered, encoding="utf-8")
    print(f"Wrote {len(names)} Paragon icon names to {OUTPUT_PATH} (v{args.version}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
