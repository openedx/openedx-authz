"""Discover, validate, compile, report, and apply the static authz schema.

This is the single non-interactive deployment command described in ADR 0019 §3.
Tutor (via a plugin init task) and other deployment systems invoke it before the
application serves traffic; all integrations share this one compiler/pipeline.

Usage::

    python manage.py load_authz_schema                 # full apply
    python manage.py load_authz_schema --dry-run       # report only, no writes
    python manage.py load_authz_schema --force         # allow role removals
    python manage.py load_authz_schema \\
        --resource openedx_authz.authz:course_roles.authz.yaml   # explicit (CI/local)

The command must run at a point where all contributing packages are installed
and Django settings/DB are available (ADR 0018 / plugin timing constraint).
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from openedx_authz.engine.schema.discovery import SchemaDiscovery, SchemaDiscoveryError
from openedx_authz.engine.schema.exceptions import SchemaError
from openedx_authz.engine.schema.pipeline import SchemaPipeline


class Command(BaseCommand):
    """Management command wrapper around :class:`SchemaPipeline`."""

    help = "Discover, validate, compile, and apply the static authorization schema."

    def add_arguments(self, parser) -> None:
        """Register command-line options."""
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Run discover through render and print the change report without writing to the database.",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Allow removing static roles that still have user assignments (ADR 0018).",
        )
        parser.add_argument(
            "--resource",
            action="append",
            default=None,
            metavar="PACKAGE:RESOURCE_PATH",
            help=(
                "Explicitly include a schema resource (repeatable), in addition to discovered "
                "entry points and settings. Intended for CI and local development."
            ),
        )

    def handle(self, *args, **options) -> None:
        """Build the pipeline and run the requested operation.

        Validation/compile/apply errors surface as CommandError so deployment
        stops before (or without partially applying) any database change.
        """
        explicit = self._parse_resource_overrides(options.get("resource"))
        discovery = SchemaDiscovery(explicit_resources=explicit) if explicit else SchemaDiscovery()
        pipeline = SchemaPipeline(discovery=discovery)

        try:
            if options.get("dry_run"):
                plan = pipeline.plan()
                self._report_plan(plan)
                return

            result = pipeline.apply(force=options.get("force", False))
        except (SchemaError, SchemaDiscoveryError) as exc:
            raise CommandError(str(exc)) from exc

        if result.unchanged:
            self.stdout.write(self.style.SUCCESS("Authz schema unchanged; no rows written."))
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Authz schema applied: {result.added} row(s) added, {result.removed} removed."
                )
            )

    def _parse_resource_overrides(self, raw: list[str] | None) -> list[tuple[str, str]]:
        """Parse ``PACKAGE:RESOURCE_PATH`` strings into tuples."""
        if not raw:
            return []
        parsed: list[tuple[str, str]] = []
        for item in raw:
            if ":" not in item:
                raise CommandError(
                    f"--resource must be 'PACKAGE:RESOURCE_PATH', got {item!r}."
                )
            package, resource_path = item.split(":", 1)
            if not package or not resource_path:
                raise CommandError(
                    f"--resource must be 'PACKAGE:RESOURCE_PATH', got {item!r}."
                )
            parsed.append((package, resource_path))
        return parsed

    def _report_plan(self, plan) -> None:
        """Print the change report (added/removed rows, blocking assignments)."""
        if plan.unchanged:
            self.stdout.write(self.style.SUCCESS("Authz schema unchanged; no rows would be written."))
            return

        self.stdout.write(f"Rows to add ({len(plan.added_rows)}):")
        for row in plan.added_rows:
            self.stdout.write(f"  + {row.as_policy()}")

        self.stdout.write(f"Stale rows detected ({len(plan.removed_rows)}) — pruning deferred:")
        for row in plan.removed_rows:
            self.stdout.write(f"  - {row.as_policy()}")

        if plan.blocking_assignments:
            self.stdout.write(
                self.style.WARNING(
                    f"{len(plan.blocking_assignments)} role(s) with existing assignments would be "
                    "removed; apply requires --force:"
                )
            )
            for role, subject in plan.blocking_assignments:
                self.stdout.write(f"  ! {role} assigned to {subject}")
