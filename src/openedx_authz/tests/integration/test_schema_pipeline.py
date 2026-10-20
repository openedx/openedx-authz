"""Exercise the complete schema pipeline with YAML fixtures and the real database."""

from unittest import mock

import pytest
from django.test import TestCase, override_settings

from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.engine.schema.discovery import SchemaDiscovery
from openedx_authz.engine.schema.exceptions import SchemaValidationError
from openedx_authz.engine.schema.pipeline import SchemaPipeline
from openedx_authz.models.schema import (
    AuthzPermissionCategory,
    AuthzPermissionDefinition,
    AuthzRoleDefinition,
    AuthzRolePermission,
    AuthzRolePermissionSource,
    AuthzSchemaSource,
)

FIXTURE_ROOT = "openedx_authz/tests/integration/fixtures/schema_pipeline"


@pytest.fixture(scope="session")
def django_db_setup(request, django_test_environment, django_db_blocker):  # pylint: disable=unused-argument
    """Build integration tables from models while platform migrations stay disabled."""
    from django.test.utils import setup_databases, teardown_databases  # pylint: disable=import-outside-toplevel
    from pytest_django.fixtures import _disable_migrations  # pylint: disable=import-outside-toplevel

    _disable_migrations()
    with django_db_blocker.unblock():
        database_config = setup_databases(verbosity=request.config.option.verbose, interactive=False)
    yield
    with django_db_blocker.unblock():
        teardown_databases(database_config, verbosity=request.config.option.verbose)


@override_settings(OPENEDX_AUTHZ_SCHEMA_DIRECTORIES=[])
class TestSchemaPipelineIntegration(TestCase):
    """Run discovery through application using packaged YAML fixtures."""

    def setUp(self):
        """Start every integration case without stored policy rows."""
        self.enforcer = AuthzEnforcer.get_enforcer()
        self.enforcer.clear_policy()

    def tearDown(self):
        """Leave no policy rows for another integration test."""
        self.enforcer.clear_policy()

    def pipeline(self, fixture_set: str) -> SchemaPipeline:
        """Build a pipeline that discovers only one packaged fixture set."""
        discovery = SchemaDiscovery(passed_in_directories=[f"{FIXTURE_ROOT}/{fixture_set}"])
        return SchemaPipeline(discovery=discovery)

    @mock.patch("openedx_authz.engine.schema.discovery.metadata.entry_points", return_value=[])
    def test_valid_fixtures_apply_and_reapply_idempotently(self, _entry_points):
        """Mixed YAML suffixes traverse every stage and persist stable provenance."""
        pipeline = self.pipeline("valid")

        first = pipeline.apply()
        second = pipeline.apply()

        self.assertEqual(first.added, 2)
        self.assertEqual(second.added, 0)
        self.assertEqual(second.removed, 0)
        self.assertTrue(second.unchanged)
        self.assertEqual(AuthzPermissionCategory.objects.filter(category_id="pipeline_content").count(), 1)
        self.assertEqual(AuthzPermissionDefinition.objects.filter(namespace="pipeline").count(), 2)
        self.assertEqual(AuthzRoleDefinition.objects.filter(role_id="pipeline_editor").count(), 1)
        self.assertEqual(AuthzRolePermission.objects.filter(role__role_id="pipeline_editor").count(), 2)
        self.assertEqual(AuthzSchemaSource.objects.filter(module__contains="schema_pipeline.valid").count(), 1)
        edit_link = AuthzRolePermissionSource.objects.get(
            role_permission__role__role_id="pipeline_editor",
            role_permission__permission__name="edit_content",
        )
        self.assertEqual(edit_link.origin_kind, "extension")

    @mock.patch("openedx_authz.engine.schema.discovery.metadata.entry_points", return_value=[])
    def test_structural_errors_from_every_file_stop_before_database_writes(self, _entry_points):
        """Structural findings aggregate across files and prevent all persistence."""
        with self.assertRaises(SchemaValidationError) as error:
            self.pipeline("invalid_structure").apply()

        source_ids = {issue.source_id for issue in error.exception.issues}
        self.assertEqual(len(source_ids), 2)
        self.assertFalse(AuthzSchemaSource.objects.exists())
        self.assertFalse(AuthzRoleDefinition.objects.exists())

    @mock.patch("openedx_authz.engine.schema.discovery.metadata.entry_points", return_value=[])
    def test_semantic_error_stops_before_database_writes(self, _entry_points):
        """Structurally valid unknown references fail semantic validation without writes."""
        with self.assertRaises(SchemaValidationError) as error:
            self.pipeline("invalid_semantics").apply()

        self.assertTrue(any("unknown category" in issue.message for issue in error.exception.issues))
        self.assertFalse(AuthzSchemaSource.objects.exists())
        self.assertFalse(AuthzPermissionDefinition.objects.exists())
