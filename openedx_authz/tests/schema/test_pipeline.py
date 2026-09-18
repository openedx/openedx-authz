"""Unit tests for the SchemaPipeline orchestrator.

The pipeline is pure wiring: it sequences discovery -> load -> validate ->
compile -> render -> plan/apply. These tests inject mocked components so the
orchestration (ordering, error propagation, delegation) is verified without a
database, Casbin, or real schema files.
"""

from unittest import mock

import pytest

from openedx_authz.engine.schema.exceptions import SchemaValidationError
from openedx_authz.engine.schema.pipeline import SchemaPipeline
from openedx_authz.engine.schema.validation import ValidationIssue


def _pipeline(*, issues=None, compiled_issues=None):
    """Build a SchemaPipeline with every component mocked.

    ``issues`` seeds the document-level validator result and ``compiled_issues``
    the post-compile one (both default to none).
    """
    discovery = mock.Mock(name="discovery")
    discovery.discover.return_value = ["resource"]

    loader = mock.Mock(name="loader")
    loader.load.return_value = ["document"]

    validator = mock.Mock(name="validator")
    validator.validate.return_value = issues or []
    validator.validate_compiled.return_value = compiled_issues or []
    validator.has_errors.side_effect = lambda found: any(i.is_error for i in found)

    compiler = mock.Mock(name="compiler")
    compiler.compile.return_value = "compiled-schema"

    renderer = mock.Mock(name="renderer")
    renderer.render.return_value = "rendered-policy"

    applier = mock.Mock(name="applier")

    pipeline = SchemaPipeline(
        discovery=discovery,
        loader=loader,
        validator=validator,
        compiler=compiler,
        renderer=renderer,
        applier=applier,
    )
    return pipeline, {
        "discovery": discovery,
        "loader": loader,
        "validator": validator,
        "compiler": compiler,
        "renderer": renderer,
        "applier": applier,
    }


class TestCompile:
    """Cover SchemaPipeline.compile step ordering and validation gating."""

    def test_runs_steps_in_order_and_returns_compiled_schema(self):
        pipeline, m = _pipeline()

        result = pipeline.compile()

        assert result == "compiled-schema"
        m["discovery"].discover.assert_called_once_with()
        m["loader"].load.assert_called_once_with(["resource"])
        m["validator"].validate.assert_called_once_with(["document"])
        m["compiler"].compile.assert_called_once_with(["document"])
        m["validator"].validate_compiled.assert_called_once_with("compiled-schema")

    def test_raises_when_compiled_schema_has_errors(self):
        """The second gate runs on the compiled schema (ADR 0017 §4).

        Extensions and priority resolution can only be checked after they are
        applied, so validation runs again post-compile.
        """
        error = ValidationIssue("error", "scope not supported", "src")
        pipeline, m = _pipeline(compiled_issues=[error])

        with pytest.raises(SchemaValidationError) as exc_info:
            pipeline.compile()

        assert exc_info.value.issues == [error]
        m["compiler"].compile.assert_called_once()

    def test_compiled_errors_stop_before_render_and_apply(self):
        error = ValidationIssue("error", "scope not supported", "src")
        pipeline, m = _pipeline(compiled_issues=[error])

        with pytest.raises(SchemaValidationError):
            pipeline.apply()

        m["renderer"].render.assert_not_called()
        m["applier"].apply.assert_not_called()

    def test_compiled_warnings_do_not_stop_compilation(self):
        warning = ValidationIssue("warning", "heads up", "src")
        pipeline, _ = _pipeline(compiled_issues=[warning])

        assert pipeline.compile() == "compiled-schema"

    def test_document_errors_skip_the_compiled_check(self):
        """A failed first gate must not reach the second one."""
        error = ValidationIssue("error", "boom", "src")
        pipeline, m = _pipeline(issues=[error])

        with pytest.raises(SchemaValidationError):
            pipeline.compile()

        m["validator"].validate_compiled.assert_not_called()

    def test_raises_when_validation_has_errors(self):
        error = ValidationIssue("error", "boom", "src")
        pipeline, m = _pipeline(issues=[error])

        with pytest.raises(SchemaValidationError) as exc_info:
            pipeline.compile()

        # Only error-level issues are carried on the exception.
        assert exc_info.value.issues == [error]
        # Compilation must not run once validation fails.
        m["compiler"].compile.assert_not_called()

    def test_warning_only_issues_do_not_stop_compilation(self):
        warning = ValidationIssue("warning", "heads up", "src")
        pipeline, m = _pipeline(issues=[warning])

        result = pipeline.compile()

        assert result == "compiled-schema"
        m["compiler"].compile.assert_called_once()


class TestPlan:
    """Cover SchemaPipeline.plan delegation to render + applier.plan."""

    def test_delegates_to_renderer_and_applier_plan(self):
        pipeline, m = _pipeline()

        result = pipeline.plan()

        m["renderer"].render.assert_called_once_with("compiled-schema")
        # The schema goes along with the rendered rows so the report can cover
        # definition changes, not just policy rows (ADR 0018 §6).
        m["applier"].plan.assert_called_once_with("rendered-policy", "compiled-schema")
        assert result is m["applier"].plan.return_value

    def test_plan_does_not_apply(self):
        pipeline, m = _pipeline()
        pipeline.plan()
        m["applier"].apply.assert_not_called()


class TestApply:
    """Cover SchemaPipeline.apply delegation and force forwarding."""

    def test_delegates_to_applier_apply_without_force(self):
        pipeline, m = _pipeline()

        result = pipeline.apply()

        m["renderer"].render.assert_called_once_with("compiled-schema")
        m["applier"].apply.assert_called_once_with("rendered-policy", "compiled-schema", force=False)
        assert result is m["applier"].apply.return_value

    def test_forwards_force_flag(self):
        pipeline, m = _pipeline()
        pipeline.apply(force=True)
        m["applier"].apply.assert_called_once_with("rendered-policy", "compiled-schema", force=True)


def test_default_components_are_constructed_when_not_injected():
    """A bare SchemaPipeline wires real default components (smoke test)."""
    pipeline = SchemaPipeline()
    # Internal defaults exist; we don't run them here (that needs real data),
    # only assert the orchestrator is fully constructed.
    # pylint: disable=protected-access
    assert pipeline._discovery is not None
    assert pipeline._loader is not None
    assert pipeline._validator is not None
    assert pipeline._compiler is not None
    assert pipeline._renderer is not None
    assert pipeline._applier is not None
