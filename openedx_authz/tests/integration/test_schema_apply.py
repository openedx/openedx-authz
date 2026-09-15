"""End-to-end integration tests for schema apply pruning (ADR 0018 §2, §5, §6).

Unlike the unit tests in ``tests/schema/test_apply.py`` (which use a fake
enforcer and stub persistence), these exercise the *real* stack:

* the shared Casbin :class:`~openedx_authz.engine.enforcer.AuthzEnforcer`
  (DB-backed adapter, production matcher), and
* the real definition/source ORM tables.

They prove the reconciliation contract from end to end: after a schema removes a
permission or a role, re-applying prunes the stale Casbin ``p`` rows and the
definition rows so enforcement and the stored schema both follow the compiled
definition. Force-removal of an assigned role removes its ``g`` assignment rows
too.

Run these in an edx-platform environment where the Casbin model/adapter and the
authz migrations are available.
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
def django_db_setup(request, django_db_blocker):
    """Create and migrate a real test database for this module.

    The integration-folder ``conftest`` intentionally makes ``django_db_setup``
    a no-op so the suite reuses an already-migrated edx-platform database. These
    schema-apply tests don't touch any platform models, so we restore standard
    database creation here to let them run standalone against the package's own
    settings while still exercising the real enforcer and ORM.
    """
    from django.test.utils import setup_databases, teardown_databases  # pylint: disable=import-outside-toplevel

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
        """Dropping a permission via extension prunes its p row; enforce flips.

        A user assigned the role is allowed the permission before the removal and
        denied it after, while an untouched permission stays allowed. This is the
        core §2 guarantee: enforcement follows the compiled schema instead of
        drifting on a stale row.
        """
        base = _document(roles=[_editor_role(("courses.view_course", "courses.manage_tags"))])
        self._apply(base)

        # Assign the role to a user in the course scope so enforce has a g edge.
        self.enforcer.add_role_for_user_in_domain(USER_SUBJECT, ROLE_SUBJECT, COURSE_SCOPE)
        self.enforcer.load_policy()

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
        self.assertFalse(self.enforcer.enforce(USER_SUBJECT, TAGS_ACTION, COURSE_SCOPE))
        self.assertTrue(self.enforcer.enforce(USER_SUBJECT, VIEW_ACTION, COURSE_SCOPE))

        # The manage_tags grant is gone from the definition tables too.
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
        self.enforcer.add_role_for_user_in_domain(USER_SUBJECT, ROLE_SUBJECT, COURSE_SCOPE)
        self.enforcer.load_policy()

        with self.assertRaises(SchemaApplyError):
            self._apply(_document(roles=[]), force=False)

        # Nothing was pruned: the p row and the definition are intact.
        self.assertEqual(len(self._p_rows_for_role()), 1)
        self.assertTrue(AuthzRoleDefinition.objects.filter(role_id="schema_apply_editor").exists())

    def test_force_removes_assigned_role_and_its_assignment(self):
        """With force, a removed role loses its p rows and g assignment (§6)."""
        self._apply(_document(roles=[_editor_role(("courses.view_course",))]))
        self.enforcer.add_role_for_user_in_domain(USER_SUBJECT, ROLE_SUBJECT, COURSE_SCOPE)
        self.enforcer.load_policy()
        self.assertTrue(self.enforcer.enforce(USER_SUBJECT, VIEW_ACTION, COURSE_SCOPE))

        result = self._apply(_document(roles=[]), force=True)

        self.assertEqual(result.removed, 1)
        self.assertEqual(self._p_rows_for_role(), [])
        self.assertFalse(self.enforcer.enforce(USER_SUBJECT, VIEW_ACTION, COURSE_SCOPE))
        # The assignment (g row) for the removed role is gone.
        self.assertEqual(
            [g for g in self.enforcer.get_grouping_policy() if g[1] == ROLE_SUBJECT],
            [],
        )
        self.assertFalse(AuthzRoleDefinition.objects.filter(role_id="schema_apply_editor").exists())
