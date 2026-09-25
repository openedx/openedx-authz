"""Unit tests for the ``load_authz_schema`` management command.

The command is a thin wrapper over :class:`SchemaPipeline`. These tests mock the
pipeline (and, where relevant, discovery) at the command module so the command's
own logic — option handling, apply vs. dry-run branching, report formatting, and
error translation to CommandError — is verified without a database.
"""

from io import StringIO
from unittest import mock

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from openedx_authz.engine.renderer import (
    ApplyResult,
    ChangePlan,
    DefinitionDiff,
    PolicyRow,
)
from openedx_authz.engine.schema.discovery import SchemaDiscoveryError
from openedx_authz.engine.schema.exceptions import (
    SchemaApplyError,
    SchemaCompileError,
    SchemaValidationError,
)

COMMAND = "load_authz_schema"
PIPELINE_PATH = "openedx_authz.management.commands.load_authz_schema.SchemaPipeline"
DISCOVERY_PATH = "openedx_authz.management.commands.load_authz_schema.SchemaDiscovery"


def _run(*args):
    """Invoke the command, capturing stdout; returns the printed text."""
    out = StringIO()
    call_command(COMMAND, *args, stdout=out)
    return out.getvalue()


class TestApplyMode:
    """Cover the default (apply) mode of the command."""

    def test_apply_reports_changes(self):
        """Apply prints the added/removed policy-row summary."""
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.apply.return_value = ApplyResult(added=3, removed=1, unchanged=False)
            output = _run()

        pipeline_cls.return_value.apply.assert_called_once_with(force=False)
        assert "3 Casbin policy row(s) added, 1 removed" in output

    def test_apply_prints_detailed_change_report(self):
        """Apply prints the same breakdown as a dry run when a plan is attached."""
        plan = ChangePlan(
            added_rows=[PolicyRow("p", "role^r", "act^courses.view_course", "course-v1^*", "allow")],
            removed_rows=[PolicyRow("p", "role^old", "act^courses.manage_tags", "course-v1^*", "allow")],
            unchanged=False,
            roles=DefinitionDiff(updated=["course_editor"]),
        )
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.apply.return_value = ApplyResult(added=1, removed=1, unchanged=False, plan=plan)
            output = _run()

        # Detailed policy-row and definition sections, using past tense.
        assert "Casbin policy rows added (1)" in output
        assert "Casbin policy rows removed (1)" in output
        assert "role^r" in output
        assert "role^old" in output
        assert "Definition changes - role (1)" in output
        assert "~ course_editor" in output
        # And still closes with the applied summary, now including definitions.
        assert "1 Casbin policy row(s) added, 1 removed; definition changes: 1 role" in output

    def test_apply_summary_counts_definition_changes_with_zero_policy_rows(self):
        """A metadata-only apply writes 0 p rows but still recaps definitions."""
        plan = ChangePlan(
            added_rows=[],
            removed_rows=[],
            unchanged=False,
            categories=DefinitionDiff(added=["course_content", "library"]),
            roles=DefinitionDiff(updated=["course_editor"]),
        )
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.apply.return_value = ApplyResult(added=0, removed=0, unchanged=False, plan=plan)
            output = _run()

        assert "0 Casbin policy row(s) added, 0 removed; definition changes: 2 category, 1 role" in output

    def test_apply_summary_omits_definitions_when_unchanged(self):
        """Row-only changes don't tack on an empty definition recap."""
        plan = ChangePlan(
            added_rows=[PolicyRow("p", "role^r", "act^courses.view_course", "course-v1^*", "allow")],
            unchanged=False,
        )
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.apply.return_value = ApplyResult(added=1, removed=0, unchanged=False, plan=plan)
            output = _run()

        assert "1 Casbin policy row(s) added, 0 removed." in output
        assert "definition changes:" not in output

    def test_apply_reports_unchanged(self):
        """An apply that changes nothing reports 'unchanged'."""
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.apply.return_value = ApplyResult(added=0, removed=0, unchanged=True)
            output = _run()

        assert "unchanged" in output.lower()

    def test_force_flag_is_forwarded(self):
        """``--force`` is passed through to ``pipeline.apply``."""
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.apply.return_value = ApplyResult(unchanged=True)
            _run("--force")

        pipeline_cls.return_value.apply.assert_called_once_with(force=True)


class TestDryRunMode:
    """Cover the --dry-run mode and its change report formatting."""

    def test_dry_run_calls_plan_not_apply(self):
        """``--dry-run`` calls ``plan`` and never ``apply``."""
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.plan.return_value = ChangePlan(unchanged=True)
            _run("--dry-run")

        pipeline_cls.return_value.plan.assert_called_once_with()
        pipeline_cls.return_value.apply.assert_not_called()

    def test_dry_run_unchanged_report(self):
        """A dry run with no diff reports 'unchanged'."""
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.plan.return_value = ChangePlan(unchanged=True)
            output = _run("--dry-run")

        assert "unchanged" in output.lower()

    def test_dry_run_reports_added_and_removed_rows(self):
        """A dry run lists the policy rows it would add and remove."""
        plan = ChangePlan(
            added_rows=[PolicyRow("p", "role^r", "act^courses.view_course", "course-v1^*", "allow")],
            removed_rows=[PolicyRow("p", "role^old", "act^courses.manage_tags", "course-v1^*", "allow")],
            unchanged=False,
        )
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.plan.return_value = plan
            output = _run("--dry-run")

        assert "Casbin policy rows to add (1)" in output
        assert "Casbin policy rows to remove (1)" in output
        assert "role^r" in output
        assert "role^old" in output

    def test_dry_run_reports_blocking_assignments(self):
        """A dry run flags assignments that would require ``--force`` to remove."""
        plan = ChangePlan(
            added_rows=[],
            removed_rows=[],
            unchanged=False,
            blocking_assignments=[("role^course_editor", "user^alice")],
        )
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.plan.return_value = plan
            output = _run("--dry-run")

        assert "requires --force" in output
        assert "role^course_editor assigned to user^alice" in output


class TestDefinitionReport:
    """The dry-run report covers definition changes too (ADR 0018 §6).

    Apply syncs the definition tables even when no ``p`` row changes, so a
    metadata-only edit has to appear in the report.
    """

    def test_metadata_only_change_is_reported_without_any_rows(self):
        """A metadata-only edit is reported even though no policy row changes."""
        plan = ChangePlan(
            added_rows=[],
            removed_rows=[],
            unchanged=False,
            roles=DefinitionDiff(updated=["course_editor"]),
        )
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.plan.return_value = plan
            output = _run("--dry-run")

        assert "Definition changes - role (1)" in output
        assert "~ course_editor" in output

    def test_added_and_removed_definitions_are_reported_per_kind(self):
        """Definition changes are grouped and labeled per kind (category/permission/grant)."""
        plan = ChangePlan(
            unchanged=False,
            categories=DefinitionDiff(added=["course_content"]),
            permissions=DefinitionDiff(removed=["courses.manage_tags"]),
            grants=DefinitionDiff(added=["course_editor -> courses.view_course @ course-v1"]),
        )
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.plan.return_value = plan
            output = _run("--dry-run")

        assert "Definition changes - category (1)" in output
        assert "+ course_content" in output
        assert "Definition changes - permission (1)" in output
        assert "- courses.manage_tags" in output
        assert "Definition changes - role-permission (1)" in output

    def test_untouched_kinds_are_omitted(self):
        """Kinds with no changes are left out of the report."""
        plan = ChangePlan(unchanged=False, roles=DefinitionDiff(added=["course_editor"]))
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.plan.return_value = plan
            output = _run("--dry-run")

        assert "Definition changes - role (1)" in output
        assert "category" not in output
        assert "permission" not in output

    def test_row_only_change_says_definitions_unchanged(self):
        """A row-only change states explicitly that definitions are unchanged."""
        plan = ChangePlan(
            added_rows=[PolicyRow("p", "role^r", "act^courses.view_course", "course-v1^*", "allow")],
            unchanged=False,
        )
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.plan.return_value = plan
            output = _run("--dry-run")

        assert "Role/permission/category definitions unchanged." in output


class TestDirectoryOption:
    """Cover the --dir option wiring into SchemaDiscovery."""

    def test_dir_builds_discovery_with_passed_in_directories(self):
        """Repeated ``--dir`` options are passed to ``SchemaDiscovery`` as directories."""
        with mock.patch(PIPELINE_PATH) as pipeline_cls, mock.patch(DISCOVERY_PATH) as discovery_cls:
            pipeline_cls.return_value.apply.return_value = ApplyResult(unchanged=True)
            _run("--dir", "pkg_a/authz/schema", "--dir", "pkg_b/authz/schema")

        discovery_cls.assert_called_once_with(passed_in_directories=["pkg_a/authz/schema", "pkg_b/authz/schema"])
        # The pipeline is built with that discovery instance.
        pipeline_cls.assert_called_once_with(discovery=discovery_cls.return_value)

    def test_no_dir_uses_default_discovery(self):
        """Without ``--dir`` the command builds a default ``SchemaDiscovery``."""
        with mock.patch(PIPELINE_PATH) as pipeline_cls, mock.patch(DISCOVERY_PATH) as discovery_cls:
            pipeline_cls.return_value.apply.return_value = ApplyResult(unchanged=True)
            _run()

        # Default discovery (no explicit directories) is constructed.
        discovery_cls.assert_called_once_with()


class TestErrorHandling:
    """Cover translation of pipeline errors into CommandError.

    Deployment must stop with a readable message rather than a traceback, and
    ``SchemaDiscoveryError`` needs handling separately because it does not
    inherit from ``SchemaError``.
    """

    def test_schema_error_becomes_command_error(self):
        """A validation error during apply is surfaced as ``CommandError``."""
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.apply.side_effect = SchemaValidationError([])
            with pytest.raises(CommandError):
                _run()

    def test_dry_run_error_becomes_command_error(self):
        """A validation error during a dry run is surfaced as ``CommandError``."""
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.plan.side_effect = SchemaValidationError([])
            with pytest.raises(CommandError):
                _run("--dry-run")

    def test_discovery_error_becomes_command_error(self):
        """ADR 0019 §1: a failing provider stops deployment, naming the app."""
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.apply.side_effect = SchemaDiscoveryError(
                "authz.schema provider 'broken_app' failed during discovery: boom"
            )
            with pytest.raises(CommandError, match="broken_app"):
                _run()

    def test_discovery_error_in_dry_run_becomes_command_error(self):
        """A discovery error during a dry run is surfaced as ``CommandError``."""
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.plan.side_effect = SchemaDiscoveryError("bad directory")
            with pytest.raises(CommandError, match="bad directory"):
                _run("--dry-run")

    def test_compile_error_becomes_command_error(self):
        """A compile error is surfaced as ``CommandError`` with its message."""
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.apply.side_effect = SchemaCompileError("equal priority conflict")
            with pytest.raises(CommandError, match="equal priority conflict"):
                _run()

    def test_apply_error_becomes_command_error(self):
        """The force gate surfaces as a message, not a traceback."""
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.apply.side_effect = SchemaApplyError("Refusing to proceed")
            with pytest.raises(CommandError, match="Refusing to proceed"):
                _run()


class TestOptionCombinations:
    """Options compose: a dry run can also take explicit directories."""

    def test_dry_run_with_dir_plans_against_that_directory(self):
        """``--dry-run`` composes with ``--dir``: it plans against the given directory."""
        with mock.patch(PIPELINE_PATH) as pipeline_cls, mock.patch(DISCOVERY_PATH) as discovery_cls:
            pipeline_cls.return_value.plan.return_value = ChangePlan(unchanged=True)
            _run("--dry-run", "--dir", "pkg_a/authz/schema")

        discovery_cls.assert_called_once_with(passed_in_directories=["pkg_a/authz/schema"])
        pipeline_cls.assert_called_once_with(discovery=discovery_cls.return_value)
        pipeline_cls.return_value.plan.assert_called_once_with()
        pipeline_cls.return_value.apply.assert_not_called()

    def test_dry_run_ignores_force(self):
        """A dry run writes nothing, so force has nothing to authorize."""
        with mock.patch(PIPELINE_PATH) as pipeline_cls:
            pipeline_cls.return_value.plan.return_value = ChangePlan(unchanged=True)
            _run("--dry-run", "--force")

        pipeline_cls.return_value.plan.assert_called_once_with()
        pipeline_cls.return_value.apply.assert_not_called()
