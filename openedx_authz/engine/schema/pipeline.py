"""End-to-end orchestration of the authz schema lifecycle (ADR 0018).

:class:`SchemaPipeline` wires the steps together:

    discover -> load -> validate -> compile -> render -> (plan) -> apply

The Casbin-free steps (discover..compile) live in :mod:`openedx_authz.engine.schema`;
render/apply live in :mod:`openedx_authz.engine.renderer`. This orchestrator is
the single entry point used by the deployment management command and by tests.

Deployment runs discover-through-apply before the application serves traffic
(ADR 0018 §2). CI/local runs may stop after ``plan`` for a dry run, or pass
explicit resources.
"""

from __future__ import annotations

import logging

from openedx_authz.engine.renderer import (
    ApplyResult,
    ChangePlan,
    PolicyRenderer,
    SchemaApplier,
)
from openedx_authz.engine.schema.compilation import SchemaCompiler
from openedx_authz.engine.schema.discovery import SchemaDiscovery
from openedx_authz.engine.schema.exceptions import SchemaValidationError
from openedx_authz.engine.schema.loading import SchemaLoader
from openedx_authz.engine.schema.types import CompiledSchema
from openedx_authz.engine.schema.validation import SchemaValidator

logger = logging.getLogger(__name__)


class SchemaPipeline:
    """Runs the schema lifecycle from discovery through apply.

    Components are injected for testability; each defaults to its standard
    implementation.
    """

    def __init__(
        self,
        *,
        discovery: SchemaDiscovery | None = None,
        loader: SchemaLoader | None = None,
        validator: SchemaValidator | None = None,
        compiler: SchemaCompiler | None = None,
        renderer: PolicyRenderer | None = None,
        applier: SchemaApplier | None = None,
    ):
        self._discovery = discovery or SchemaDiscovery()
        self._loader = loader or SchemaLoader(self._discovery)
        self._validator = validator or SchemaValidator()
        self._compiler = compiler or SchemaCompiler()
        self._renderer = renderer or PolicyRenderer()
        self._applier = applier or SchemaApplier()

    def compile(self) -> CompiledSchema:
        """Run discover -> load -> validate -> compile and return the result.

        Raises:
            SchemaValidationError: If validation finds error-level issues.
            SchemaCompileError: On an unresolvable conflict.
        """
        resources = self._discovery.discover()
        documents = self._loader.load(resources)

        issues = self._validator.validate(documents)
        for issue in issues:
            log = logger.error if issue.is_error else logger.warning
            log("authz schema %s: %s [%s]", issue.level, issue.message, issue.source_id or "-")
        if self._validator.has_errors(issues):
            raise SchemaValidationError([i for i in issues if i.is_error])

        return self._compiler.compile(documents)

    def plan(self) -> ChangePlan:
        """Run through render and produce the change report without writing.

        Used for dry-run / CI review (ADR 0018 §6).
        """
        schema = self.compile()
        rendered = self._renderer.render(schema)
        return self._applier.plan(rendered)

    def apply(self, *, force: bool = False) -> ApplyResult:
        """Run the full lifecycle and persist the result transactionally.

        Args:
            force: Allow removal of roles that still have assignments (ADR 0018).
        """
        schema = self.compile()
        rendered = self._renderer.render(schema)
        return self._applier.apply(rendered, schema, force=force)
