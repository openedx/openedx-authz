"""Discover, validate, compile, report, and apply the static authz schema.

This is the single non-interactive deployment command described in ADR 0019 §3.
Tutor (via a plugin init task) and other deployment systems invoke it before the
application serves traffic; all integrations share this one compiler/pipeline.

Usage::

    python manage.py load_authz_schema                 # full apply
    python manage.py load_authz_schema --dry-run       # report only, no writes
    python manage.py load_authz_schema --force         # allow role removals
    python manage.py load_authz_schema \\
        --dir openedx_authz/authz/schema               # explicit directory (CI/local)

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
            "--dir",
            action="append",
            default=None,
            dest="directories",
            metavar="DIRECTORY",
            help=(
                "Explicitly include a schema directory (repeatable), in addition to discovered "
                "entry points and settings. The loader reads every .yaml file in it. "
                "Path format is 'top_level_package/sub/dir' (e.g. 'openedx_authz/authz/schema'). "
                "Intended for CI and local development."
            ),
        )

    def handle(self, *args, **options) -> None:
        """Build the pipeline and run the requested operation.

        Validation/compile/apply errors surface as CommandError so deployment
        stops before (or without partially applying) any database change.
        """
        directories = options.get("directories") or []
        discovery = SchemaDiscovery(explicit_directories=directories) if directories else SchemaDiscovery()
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
                self.style.SUCCESS(f"Authz schema applied: {result.added} row(s) added, {result.removed} removed.")
            )

    def _report_plan(self, plan) -> None:
        """Print the change report (ADR 0018 §6).

        Covers the definition tables as well as the policy rows: apply syncs
        definitions even when no ``p`` row changes, so a metadata-only edit is a
        real change the operator needs to see before it lands.
        """
        if plan.unchanged:
            self.stdout.write(self.style.SUCCESS("Authz schema unchanged; nothing would be written."))
            return

        self.stdout.write(f"Rows to add ({len(plan.added_rows)}):")
        for row in plan.added_rows:
            self.stdout.write(f"  + {row.as_policy()}")

        self.stdout.write(f"Rows to remove ({len(plan.removed_rows)}):")
        for row in plan.removed_rows:
            self.stdout.write(f"  - {row.as_policy()}")

        self._report_definitions(plan)

        if plan.blocking_assignments:
            self.stdout.write(
                self.style.WARNING(
                    f"{len(plan.blocking_assignments)} role(s) with existing assignments would be "
                    "removed; apply requires --force:"
                )
            )
            for role, subject in plan.blocking_assignments:
                self.stdout.write(f"  ! {role} assigned to {subject}")

    def _report_definitions(self, plan) -> None:
        """Print the definition-level changes, one section per kind."""
        if plan.definitions_unchanged:
            self.stdout.write("Definitions unchanged.")
            return

        for label, diff in plan.definition_diffs:
            if diff.is_empty:
                continue
            self.stdout.write(f"Definition changes - {label} ({len(diff)}):")
            for key in diff.added:
                self.stdout.write(f"  + {key}")
            for key in diff.updated:
                self.stdout.write(f"  ~ {key}")
            for key in diff.removed:
                self.stdout.write(f"  - {key}")
