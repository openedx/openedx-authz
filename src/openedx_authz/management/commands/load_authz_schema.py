"""Discover, validate, compile, report, and apply the static authz schema.

This is the single non-interactive deployment command described in ADR 0019 §3.
Tutor (via a plugin init task) and other deployment systems invoke it before the
application serves traffic; all integrations share this one compiler/pipeline.

Usage::

    python manage.py load_authz_schema                 # full apply
    python manage.py load_authz_schema --dry-run       # report only, no writes
    python manage.py load_authz_schema --force         # allow role removals
    python manage.py load_authz_schema --drop-custom-role-permissions  # drop custom role grants
    python manage.py load_authz_schema \\
        --dir openedx_authz/applets/content_libraries/schema  # explicit directory

The command must run at a point where all contributing packages are installed
and Django settings/DB are available (ADR 0018 / plugin timing constraint).
"""

from __future__ import annotations

from typing import Callable

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
            "--drop-custom-role-permissions",
            action="store_true",
            dest="drop_custom_role_permissions",
            help=(
                "Allow removing the grants that custom roles hold of permissions the schema no longer "
                "declares. Without it, the deployment stops before any write (ADR 0035)."
            ),
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
                "Path format is 'top_level_package/sub/dir' "
                "(e.g. 'openedx_authz/applets/content_libraries/schema'). "
                "Intended for CI and local development."
            ),
        )

    def handle(self, *args, **options) -> None:
        """Build the pipeline and run the requested operation.

        Validation/compile/apply errors surface as CommandError so deployment
        stops before (or without partially applying) any database change.
        """
        self._write_banner()

        directories = options.get("directories") or []
        discovery = SchemaDiscovery(passed_in_directories=directories) if directories else SchemaDiscovery()
        pipeline = SchemaPipeline(discovery=discovery)

        try:
            if options.get("dry_run"):
                plan = pipeline.plan()
                self._report_plan(plan)
                self.stdout.write(self.style.SUCCESS("\nDry run: no changes were applied."))
                return

            result = pipeline.apply(
                force=options.get("force", False),
                drop_custom_role_permissions=options.get("drop_custom_role_permissions", False),
            )
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
        self.stdout.write(self.style.SUCCESS(f"\n{self._apply_summary(result)}"))

    def _apply_summary(self, result) -> str:
        """One-line recap of what apply wrote, across both layers.

        Reports the Casbin ``p`` row counts and the definition-metadata counts
        (roles/permissions/categories/grants) together, since either layer can
        change on its own — a metadata-only edit writes 0 policy rows but is
        still a real change the operator should see reflected here.
        """
        added = result.added + result.added_action_rows
        removed = result.removed + result.removed_action_rows
        summary = f"Authz schema applied: {added} Casbin policy row(s) added, {removed} removed"

        plan = result.plan
        if plan is not None and not plan.definitions_unchanged:
            parts = [f"{len(diff)} {label}" for label, diff in plan.definition_diffs if not diff.is_empty]
            summary += f"; definition changes: {', '.join(parts)}"

        return f"{summary}."

    def _write_banner(self) -> None:
        """Write the command banner that opens every run.

        This output is emitted mid-deployment (e.g. interleaved into a Tutor
        launch log), so every path — dry-run, apply, and both "unchanged"
        short-circuits — must be attributable to ``load_authz_schema`` without
        surrounding context. Emitting it once at the top of ``handle`` covers
        them all, including the early returns that never reach the change report.
        ``MIGRATE_HEADING`` is bold on a tty and plain text otherwise.
        """
        self.stdout.write(self.style.MIGRATE_HEADING("[load_authz_schema] Loading authorization schema"))

    def _write_marked_line(self, marker: str, text: str, style: Callable[[str], str]) -> None:
        """Write one ``  {marker} {text}`` line, colorized via Django's ``style``.

        Centralizing this keeps the literal marker character and the color that
        decorates it paired in one place, so the two layers below (Casbin rows,
        definitions) can't drift out of sync with each other on how a given kind
        of change is marked. ``style`` is one of ``self.style.SUCCESS`` /
        ``WARNING`` / ``ERROR``; Django's style wrappers pass text through
        unchanged when stdout isn't a tty, so the marker stays readable without
        color (requirement: markers are real text, not color-only).
        """
        self.stdout.write(style(f"  {marker} {text}"))

    def _write_section_header(self, text: str) -> None:
        """Write a bold section header preceded by a blank line.

        ``MIGRATE_HEADING`` is Django's built-in bold heading style; like the
        other ``self.style`` wrappers it emits bold ANSI on a tty and plain text
        otherwise, so the header stays readable (and the leading blank line
        separates each section) with or without color.
        """
        self.stdout.write(self.style.MIGRATE_HEADING(f"\n{text}"))

    @staticmethod
    def _format_policy_row(row) -> str:
        """Render a Casbin row as its policy line, e.g. ``p, role^x, act^y, scope^*, allow``.

        ``row.as_policy()`` returns the enforcer arg form (a ``list[str]``) used
        when talking to Casbin; for the human-facing report we prefix the row's
        policy type (``row.PTYPE`` — ``p`` for a permission row, ``g`` for a
        grouping row) and comma-join the fields, matching how a Casbin policy
        line is written in a model/policy file. The underlying ``as_policy``
        contract is left untouched since the enforcer depends on the list form.
        """
        return ", ".join([row.PTYPE, *row.as_policy()])

    def _report_plan(self, plan, *, applied: bool = False) -> None:
        """Print the change report (ADR 0018 §6).

        Covers the definition tables (roles, permissions, categories, and
        role-permission grants) as well as the Casbin ``p`` policy rows. The two
        are reported as separate top-level sections because they are distinct
        layers: apply syncs the definition metadata even when no ``p`` row
        changes, so a metadata-only edit is a real change the operator needs to
        see. Each layer is one compact, interleaved diff (additions and removals
        together) rather than split by direction, so a reviewer can scan one
        block per layer instead of hunting across separate add/remove sections.

        ``applied`` is True when the report describes a finished apply rather than
        a dry run. An apply only gets past the ``--force`` and
        ``--drop-custom-role-permissions`` gates with those options, so its report
        lists what they removed instead of what they would require.
        """
        if plan.unchanged:
            self.stdout.write(self.style.SUCCESS("Authz schema unchanged; nothing would be written."))
            return

        self.stdout.write("\nChanges applied:" if applied else "\nChanges to apply:")

        removed_rows = plan.removed_rows + plan.unlinked_custom_rows if applied else plan.removed_rows
        added_rows = [*plan.added_rows, *plan.added_action_rows]
        removed_rows = [*removed_rows, *plan.removed_action_rows]
        total_rows = len(added_rows) + len(removed_rows)
        if total_rows:
            self._write_section_header(f"Casbin policies ({total_rows})")
            for row in added_rows:
                self._write_marked_line("+", self._format_policy_row(row), self.style.SUCCESS)
            for row in removed_rows:
                self._write_marked_line("-", self._format_policy_row(row), self.style.ERROR)

        self._report_definitions(plan)
        self._report_unlinked_custom_grants(plan, applied=applied)
        self._report_emptied_custom_roles(plan, applied=applied)
        self._report_blocking_assignments(plan, applied=applied)

    def _report_blocking_assignments(self, plan, *, applied: bool) -> None:
        """Print the assignments of removed static roles, which only ``--force`` removes."""
        if not plan.blocking_assignments:
            return

        count = len(plan.blocking_assignments)
        if applied:
            self.stdout.write(self.style.WARNING(f"{count} assignment(s) of removed roles were removed:"))
        else:
            self.stdout.write(
                self.style.WARNING(
                    f"{count} role(s) with existing assignments would be removed; apply requires --force:"
                )
            )
        for role, subject in plan.blocking_assignments:
            self.stdout.write(f"  ! {role} assigned to {subject}")

    def _report_unlinked_custom_grants(self, plan, *, applied: bool) -> None:
        """Print the custom role grants of permissions the schema no longer declares (ADR 0035).

        The deployment drops them only when ``--drop-custom-role-permissions`` is passed, and
        stops before any write otherwise, so a dry run shows exactly which grants are affected
        before the operator chooses.
        """
        if not plan.unlinked_custom_grants:
            return

        count = len(plan.unlinked_custom_grants)
        if applied:
            self._write_section_header(f"Dropped custom role grants of removed permissions ({count})")
        else:
            self._write_section_header(f"Custom role grants of removed permissions ({count})")
        for role, permission, scope in plan.unlinked_custom_grants:
            self._write_marked_line("-" if applied else "!", f"{role} -> {permission} @ {scope}", self.style.WARNING)
        if not applied:
            self.stdout.write(
                self.style.WARNING(
                    "Apply stops here unless --drop-custom-role-permissions is passed, which drops these "
                    "grants and their Casbin policies."
                )
            )

    def _report_emptied_custom_roles(self, plan, *, applied: bool) -> None:
        """Print the custom roles that dropping the unlinked grants leaves with no permissions.

        Such a role stays, with its assignments, so administrators need to know to add
        permissions to it or remove it.
        """
        if not plan.emptied_custom_roles:
            return

        verb = "has" if applied else "would have"
        self._write_section_header(f"Custom roles left with no permissions ({len(plan.emptied_custom_roles)})")
        for role in plan.emptied_custom_roles:
            self._write_marked_line("!", f"{role} {verb} no permissions; its assignments stay", self.style.WARNING)

    def _report_definitions(self, plan) -> None:
        """Print the definition-metadata changes as one compact, interleaved diff.

        These are the role/permission/category/grant records, a separate layer
        from the Casbin policy rows above: they can change on their own (e.g. a
        display-name edit) without adding or removing any ``p`` row. The single
        header no longer names the kind (there's only one header for the whole
        section), so each line is made self-describing with an inline
        ``{label}: `` prefix, keeping the existing per-kind iteration order and
        the existing added-then-updated-then-removed order within each kind.
        """
        if plan.definitions_unchanged:
            self.stdout.write("Role/permission/category definitions unchanged.")
            return

        total = sum(len(diff) for _, diff in plan.definition_diffs)
        self._write_section_header(f"Definitions ({total})")
        for label, diff in plan.definition_diffs:
            if diff.is_empty:
                continue
            for key in diff.added:
                self._write_marked_line("+", f"{label}: {key}", self.style.SUCCESS)
            for key in diff.updated:
                self._write_marked_line("~", f"{label}: {key}", self.style.WARNING)
            for key in diff.removed:
                self._write_marked_line("-", f"{label}: {key}", self.style.ERROR)
