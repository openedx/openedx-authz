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
        discovery = SchemaDiscovery(passed_in_directories=directories) if directories else SchemaDiscovery()
        pipeline = SchemaPipeline(discovery=discovery)

        try:
            if options.get("dry_run"):
                plan = pipeline.plan()
                self._report_plan(plan, applied=False)
                return

            result = pipeline.apply(force=options.get("force", False))
        except (SchemaError, SchemaDiscoveryError) as exc:
            raise CommandError(str(exc)) from exc

        if result.unchanged:
            self.stdout.write(self.style.SUCCESS("Authz schema unchanged; no rows written."))
            return

        # Print the same detailed breakdown a dry run would, so an operator can
        # see exactly which Casbin policy rows and definition records changed,
        # then close with the applied summary.
        if result.plan is not None:
            self._report_plan(result.plan, applied=True)
        self.stdout.write(self.style.SUCCESS(self._apply_summary(result)))

    def _apply_summary(self, result) -> str:
        """One-line recap of what apply wrote, across both layers.

        Reports the Casbin ``p`` row counts and the definition-metadata counts
        (roles/permissions/categories/grants) together, since either layer can
        change on its own — a metadata-only edit writes 0 policy rows but is
        still a real change the operator should see reflected here.
        """
        summary = f"Authz schema applied: {result.added} Casbin policy row(s) added, {result.removed} removed"

        plan = result.plan
        if plan is not None and not plan.definitions_unchanged:
            parts = [f"{len(diff)} {label}" for label, diff in plan.definition_diffs if not diff.is_empty]
            summary += f"; definition changes: {', '.join(parts)}"

        return f"{summary}."

    def _report_plan(self, plan, *, applied: bool) -> None:
        """Print the change report (ADR 0018 §6).

        Covers the definition tables (roles, permissions, categories, and
        role-permission grants) as well as the Casbin ``p`` policy rows. The two
        are reported separately because they are distinct layers: apply syncs the
        definition metadata even when no ``p`` row changes, so a metadata-only
        edit is a real change the operator needs to see. ``applied`` only changes
        the verb tense in the section headers (past tense once written).
        """
        if plan.unchanged:
            self.stdout.write(self.style.SUCCESS("Authz schema unchanged; nothing would be written."))
            return

        added_label = "added" if applied else "to add"
        removed_label = "removed" if applied else "to remove"

        self.stdout.write(f"Casbin policy rows {added_label} ({len(plan.added_rows)}):")
        for row in plan.added_rows:
            self.stdout.write(f"  + {row.as_policy()}")

        self.stdout.write(f"Casbin policy rows {removed_label} ({len(plan.removed_rows)}):")
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
        """Print the definition-metadata changes, one section per kind.

        These are the role/permission/category/grant records, a separate layer
        from the Casbin policy rows above: they can change on their own (e.g. a
        display-name edit) without adding or removing any ``p`` row.
        """
        if plan.definitions_unchanged:
            self.stdout.write("Role/permission/category definitions unchanged.")
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
