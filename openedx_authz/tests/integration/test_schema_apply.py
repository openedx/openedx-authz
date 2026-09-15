"""End-to-end integration tests for schema apply pruning (ADR 0018 §2, §5, §6).

Unlike the unit tests in ``tests/schema/test_apply.py`` (which use a fake
enforcer and stub persistence), these exercise the *real* stack:

* the shared Casbin :class:`~openedx_authz.engine.enforcer.AuthzEnforcer`
  (DB-backed adapter, production matcher), and
* the real definition/source ORM tables.

They prove the reconciliation contract from end to end: after a schema removes a
permission or a role, re-applying prunes the stale Casbin ``p`` rows and the
definition rows so the stored schema follows the compiled definition, and
force-removal of an assigned role removes its ``g`` assignment rows too.

The tests assert at the behavioral level with ``enforce()`` (a permission
removal flips a real allow into a deny; force-removal revokes access) and back
that up with the stored ``p``/``g`` rows and the definition tables. They still
require no populated platform data: the staff/superuser matcher returns ``False``
for an unknown user (so no ``auth_user`` row is needed and access comes purely
from the role assignment), and scope matching is in-memory (no
``course_overviews_courseoverview`` lookup). Assignments are seeded with the
low-level grouping API to avoid the assignment audit/signal machinery.

Database setup: the integration ``conftest`` makes ``django_db_setup`` a no-op so
its other tests reuse an externally provisioned database. This module instead
restores a real setup that builds tables **directly from the models
(``run_syncdb``) with migrations disabled**. Running edx-platform migrations on
the sqlite test DB fails (some platform migrations introspect tables at import
time, e.g. ``course_overviews.0009_readd_facebook_url``), which is why the
platform itself runs tests with ``--nomigrations``. Building from models
sidesteps that and still creates every table these tests touch.

Run these in an edx-platform environment (e.g. tutor)::

    pytest -p no:randomly --create-db --ds=cms.envs.test \\
        /mnt/openedx-authz/openedx_authz/tests/integration/test_schema_apply.py
"""

from __future__ import annotations

import pytest
from django.test import TestCase

from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.engine.renderer import PolicyRenderer, SchemaApplier
from openedx_authz.engine.schema.compilation import SchemaCompiler
from openedx_authz.engine.schema.exceptions import SchemaApplyError
from openedx_authz.engine.schema.types import (
    PermissionCategory,
    PermissionDefinition,
    RoleDefinition,
    RoleExtension,
    SchemaDocument,
    SourceRecord,
)
from openedx_authz.models.schema import AuthzRoleDefinition, AuthzRolePermission


@pytest.fixture(scope="session")
def django_db_setup(request, django_test_environment, django_db_blocker):  # pylint: disable=unused-argument
    """Build the test database from models, with migrations disabled.

    Overrides both pytest-django's default (which would run migrations) and the
    integration ``conftest`` no-op (which would build nothing). Migrations are
    disabled because some edx-platform migrations fail on the sqlite test DB by
    introspecting tables at import time; ``run_syncdb`` creates the tables from
    the installed models instead, which is enough for these tests.
    """
    from django.test.utils import setup_databases, teardown_databases  # pylint: disable=import-outside-toplevel
    from pytest_django.fixtures import _disable_migrations  # pylint: disable=import-outside-toplevel

    _disable_migrations()
    with django_db_blocker.unblock():
        db_cfg = setup_databases(verbosity=request.config.option.verbose, interactive=False)
    yield
    with django_db_blocker.unblock():
        teardown_databases(db_cfg, verbosity=request.config.option.verbose)


SCOPE_NAMESPACE = "course-v1"
COURSE_SCOPE = "course-v1^course-v1:OpenedX+DemoX+DemoCourse"
USER_SUBJECT = "user^schema_apply_alice"
ROLE_SUBJECT = "role^schema_apply_editor"
VIEW_ACTION = "act^courses.view_course"
TAGS_ACTION = "act^courses.manage_tags"


def _source(name: str) -> SourceRecord:
    return SourceRecord(
        distribution="openedx-authz",
        distribution_version="0.0.0",
        module=f"openedx_authz.tests.{name}",
        resource_path=f"{name}.authz.yaml",
        schema_version="1.0",
        content_digest=f"digest-{name}",
    )


def _document(name="core", *, priority=100, roles=(), extensions=()):
    return SchemaDocument(
        source=_source(name),
        priority=priority,
        categories=[PermissionCategory(id="cat", display_name="Cat", description="d")],
        permissions=[
            PermissionDefinition(
                namespace="courses",
                name="view_course",
                display_name="View",
                description="d",
                category="cat",
                scopes=(SCOPE_NAMESPACE,),
            ),
            PermissionDefinition(
                namespace="courses",
                name="manage_tags",
                display_name="Tags",
                description="d",
                category="cat",
                scopes=(SCOPE_NAMESPACE,),
            ),
        ],
        roles=list(roles),
        role_extensions=list(extensions),
    )


def _editor_role(permissions):
    return RoleDefinition(
        id="schema_apply_editor",
        display_name="Editor",
        description="d",
        scopes=(SCOPE_NAMESPACE,),
        permissions=tuple(permissions),
    )


class SchemaApplyPruningIntegrationTests(TestCase):
    """Real enforcer + real DB reconciliation across successive applies."""

    def setUp(self):
        """Start each test from a clean policy and a known enforcer instance."""
        self.enforcer = AuthzEnforcer.get_enforcer()
        self.enforcer.clear_policy()
        self.applier = SchemaApplier()

    def tearDown(self):
        """Leave no policy behind for other integration tests."""
        self.enforcer.clear_policy()

    # -- helpers ------------------------------------------------------------

    def _apply(self, *documents, force=False):
        """Compile, render, and apply ``documents``, then reload the enforcer."""
        schema = SchemaCompiler().compile(list(documents))
        rendered = PolicyRenderer().render(schema)
        result = self.applier.apply(rendered, schema, force=force)
        self.enforcer.load_policy()
        return result

    def _p_rows_for_role(self):
        """Return the stored ``p`` rows whose subject is the test role."""
        return [row for row in self.enforcer.get_policy() if row[0] == ROLE_SUBJECT]

    def _grouping_for_role(self):
        """Return the stored ``g`` (assignment) rows referencing the test role."""
        return [g for g in self.enforcer.get_grouping_policy() if len(g) >= 2 and g[1] == ROLE_SUBJECT]

    def _assign_user_to_role(self):
        """Add a raw ``g`` assignment row for the test role.

        Uses the low-level grouping API rather than the public role-assignment
        API so the test doesn't depend on the assignment audit/signal machinery.
        The staff/superuser matcher returns ``False`` for an unknown user (no
        ``User`` row required), so enforcement decisions come purely from this
        role assignment.
        """
        self.enforcer.add_grouping_policy(USER_SUBJECT, ROLE_SUBJECT, COURSE_SCOPE)
        self.enforcer.load_policy()

    # -- tests --------------------------------------------------------------

    def test_first_apply_persists_rows_and_definitions(self):
        """A first apply writes p rows and definition tables together."""
        result = self._apply(_document(roles=[_editor_role(("courses.view_course", "courses.manage_tags"))]))

        self.assertEqual(result.added, 2)
        self.assertEqual(result.removed, 0)
        self.assertEqual(len(self._p_rows_for_role()), 2)

        editor = AuthzRoleDefinition.objects.get(role_id="schema_apply_editor")
        self.assertEqual(editor.role_permissions.count(), 2)

    def test_reapply_identical_schema_is_idempotent(self):
        """Re-applying the same schema changes nothing (ADR 0018 §2)."""
        doc = _document(roles=[_editor_role(("courses.view_course", "courses.manage_tags"))])
        self._apply(doc)

        result = self._apply(doc)

        self.assertEqual(result.added, 0)
        self.assertEqual(result.removed, 0)
        self.assertTrue(result.unchanged)
        self.assertEqual(len(self._p_rows_for_role()), 2)

    def test_removed_permission_prunes_p_row_and_flips_enforcement(self):
        """Dropping a permission via extension flips the live enforcement result.

        This is the core §2 guarantee, checked at the behavioral level: a user
        assigned the role is *allowed* ``manage_tags`` before the removal and
        *denied* it afterwards, while the untouched ``view_course`` stays
        allowed. Stored ``p`` rows and the definition tables are checked too, so
        a regression that left enforcement drifting on a stale row would fail
        here.
        """
        base = _document(roles=[_editor_role(("courses.view_course", "courses.manage_tags"))])
        self._apply(base)
        self._assign_user_to_role()

        # Before removal: both actions enforce as allowed via the role.
        self.assertTrue(self.enforcer.enforce(USER_SUBJECT, TAGS_ACTION, COURSE_SCOPE))
        self.assertTrue(self.enforcer.enforce(USER_SUBJECT, VIEW_ACTION, COURSE_SCOPE))

        # Remove manage_tags from the role via a higher-priority extension.
        extension_doc = _document(
            "modx",
            priority=200,
            roles=[],
            extensions=[RoleExtension(role="schema_apply_editor", remove_permissions=("courses.manage_tags",))],
        )
        result = self._apply(base, extension_doc)

        self.assertEqual(result.removed, 1)

        # After removal: manage_tags is denied, view_course still allowed.
        self.assertFalse(self.enforcer.enforce(USER_SUBJECT, TAGS_ACTION, COURSE_SCOPE))
        self.assertTrue(self.enforcer.enforce(USER_SUBJECT, VIEW_ACTION, COURSE_SCOPE))

        # The stale p row is gone from the stored policy...
        stored = self.enforcer.get_policy()
        self.assertNotIn([ROLE_SUBJECT, TAGS_ACTION, "course-v1^*", "allow"], stored)
        self.assertIn([ROLE_SUBJECT, VIEW_ACTION, "course-v1^*", "allow"], stored)

        # ...and from the definition tables.
        editor = AuthzRoleDefinition.objects.get(role_id="schema_apply_editor")
        self.assertEqual(editor.role_permissions.count(), 1)
        self.assertFalse(
            AuthzRolePermission.objects.filter(
                role=editor, permission__namespace="courses", permission__name="manage_tags"
            ).exists()
        )

    def test_removed_role_without_assignments_is_pruned(self):
        """A role no longer in the schema is removed when nothing is assigned."""
        self._apply(_document(roles=[_editor_role(("courses.view_course",))]))
        self.assertTrue(AuthzRoleDefinition.objects.filter(role_id="schema_apply_editor").exists())

        # Apply a schema without the role at all.
        result = self._apply(_document(roles=[]))

        self.assertEqual(result.removed, 1)
        self.assertEqual(self._p_rows_for_role(), [])
        self.assertFalse(AuthzRoleDefinition.objects.filter(role_id="schema_apply_editor").exists())

    def test_removing_assigned_role_requires_force(self):
        """Removing a role with a live assignment aborts without force (§6)."""
        self._apply(_document(roles=[_editor_role(("courses.view_course",))]))
        self._assign_user_to_role()

        with self.assertRaises(SchemaApplyError):
            self._apply(_document(roles=[]), force=False)

        # Nothing was pruned: the p row, the assignment, and the definition are
        # intact, and the user still enforces as allowed.
        self.assertEqual(len(self._p_rows_for_role()), 1)
        self.assertEqual(len(self._grouping_for_role()), 1)
        self.assertTrue(AuthzRoleDefinition.objects.filter(role_id="schema_apply_editor").exists())
        self.assertTrue(self.enforcer.enforce(USER_SUBJECT, VIEW_ACTION, COURSE_SCOPE))

    def test_force_removes_assigned_role_and_its_assignment(self):
        """With force, a removed role loses its p rows, g assignment, and access (§6)."""
        self._apply(_document(roles=[_editor_role(("courses.view_course",))]))
        self._assign_user_to_role()
        self.assertEqual(len(self._p_rows_for_role()), 1)
        self.assertEqual(len(self._grouping_for_role()), 1)
        self.assertTrue(self.enforcer.enforce(USER_SUBJECT, VIEW_ACTION, COURSE_SCOPE))

        result = self._apply(_document(roles=[]), force=True)

        self.assertEqual(result.removed, 1)
        # Access is revoked, and both the p rows and the g assignment are gone.
        self.assertFalse(self.enforcer.enforce(USER_SUBJECT, VIEW_ACTION, COURSE_SCOPE))
        self.assertEqual(self._p_rows_for_role(), [])
        self.assertEqual(self._grouping_for_role(), [])
        self.assertFalse(AuthzRoleDefinition.objects.filter(role_id="schema_apply_editor").exists())
