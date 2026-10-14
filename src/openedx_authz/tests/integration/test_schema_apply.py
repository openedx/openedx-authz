"""End-to-end integration tests for schema apply pruning (ADR 0018 §2, §5, §6, §8).

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

import threading
import time
from unittest import mock

import pytest
from django.db import IntegrityError, connection, connections
from django.test import TestCase, TransactionTestCase

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
from openedx_authz.models.core import RoleAssignmentAudit
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
                category_id="cat",
                scopes=(SCOPE_NAMESPACE,),
            ),
            PermissionDefinition(
                namespace="courses",
                name="manage_tags",
                display_name="Tags",
                description="d",
                category_id="cat",
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


class SchemaApplyIntegrationBase(TestCase):
    """Shared setup and helpers for the real-stack apply tests.

    Holds no test methods; the concrete cases below inherit the clean-policy
    setup and the ``p``/``g`` inspection helpers.
    """

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


class TestSchemaApplyPruningIntegration(SchemaApplyIntegrationBase):
    """Real enforcer + real DB reconciliation across successive applies."""

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
            extensions=[RoleExtension(role_id="schema_apply_editor", remove_permissions=("courses.manage_tags",))],
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

        # Run on_commit hooks so the ROLE_ASSIGNMENT_DELETED audit event fires.
        with self.captureOnCommitCallbacks(execute=True):
            result = self._apply(_document(roles=[]), force=True)

        self.assertEqual(result.removed, 1)
        # Access is revoked, and both the p rows and the g assignment are gone.
        self.assertFalse(self.enforcer.enforce(USER_SUBJECT, VIEW_ACTION, COURSE_SCOPE))
        self.assertEqual(self._p_rows_for_role(), [])
        self.assertEqual(self._grouping_for_role(), [])
        self.assertFalse(AuthzRoleDefinition.objects.filter(role_id="schema_apply_editor").exists())

        # Every assignment change leaves an audit trail: the force removal emits
        # ROLE_ASSIGNMENT_DELETED, which is recorded as a 'deleted' audit row.
        audit = RoleAssignmentAudit.objects.filter(subject=USER_SUBJECT, role=ROLE_SUBJECT, scope=COURSE_SCOPE)
        self.assertEqual(audit.count(), 1)
        self.assertEqual(audit.get().operation, RoleAssignmentAudit.OPERATIONS.deleted)


class TestSchemaApplyAdoptionIntegration(SchemaApplyIntegrationBase):
    """Pre-existing policy rows are adopted, unmanaged rows are left alone.

    ADR 0025 §6: a rendered ``(role, permission, scope)`` that already exists as
    a ``p`` row gains definition and source records instead of being rewritten,
    while a stored row no schema declares stays in place and enforceable but
    unattributed. This is the realistic first deployment, where ``load_policies``
    has already written the ``p`` rows and the definition tables are empty.
    """

    UNMANAGED_ROLE = "role^schema_apply_legacy"

    def _seed_rendered_rows(self, *documents):
        """Write the rendered rows straight to the policy, bypassing apply."""
        schema = SchemaCompiler().compile(list(documents))
        for row in PolicyRenderer().render(schema).rows:
            self.enforcer.add_policy(*row.as_policy())
        self.enforcer.load_policy()

    def test_preexisting_rows_are_adopted_not_duplicated(self):
        """Pre-existing rendered rows are adopted (gain definitions), not duplicated."""
        document = _document(roles=[_editor_role(("courses.view_course", "courses.manage_tags"))])
        self._seed_rendered_rows(document)
        self.assertEqual(len(self._p_rows_for_role()), 2)
        self.assertFalse(AuthzRoleDefinition.objects.filter(role_id="schema_apply_editor").exists())

        result = self._apply(document)

        # Nothing to write to the policy, yet the definitions now exist — so the
        # run is reported as a change even though no p row moved.
        self.assertEqual(result.added, 0)
        self.assertEqual(result.removed, 0)
        self.assertFalse(result.unchanged)
        self.assertEqual(len(self._p_rows_for_role()), 2)
        editor = AuthzRoleDefinition.objects.get(role_id="schema_apply_editor")
        self.assertEqual(editor.role_permissions.count(), 2)

    def test_adopted_rows_keep_enforcing(self):
        """Adoption must not interrupt access that already worked."""
        document = _document(roles=[_editor_role(("courses.view_course",))])
        self._seed_rendered_rows(document)
        self._assign_user_to_role()
        self.assertTrue(self.enforcer.enforce(USER_SUBJECT, VIEW_ACTION, COURSE_SCOPE))

        self._apply(document)

        self.assertTrue(self.enforcer.enforce(USER_SUBJECT, VIEW_ACTION, COURSE_SCOPE))

    def test_adopted_grant_records_the_contributing_source(self):
        """An adopted grant records its contributing source module."""
        document = _document(roles=[_editor_role(("courses.view_course",))])
        self._seed_rendered_rows(document)

        self._apply(document)

        grant = AuthzRolePermission.objects.get(role__role_id="schema_apply_editor")
        self.assertEqual([source.module for source in grant.sources.all()], ["openedx_authz.tests.core"])

    def test_unmanaged_row_is_preserved_and_still_enforces(self):
        """A row no schema declares is not the loader's to remove."""
        self.enforcer.add_policy(self.UNMANAGED_ROLE, VIEW_ACTION, "course-v1^*", "allow")
        self.enforcer.add_grouping_policy(USER_SUBJECT, self.UNMANAGED_ROLE, COURSE_SCOPE)
        self.enforcer.load_policy()

        result = self._apply(_document(roles=[_editor_role(("courses.view_course",))]))

        self.assertEqual(result.removed, 0)
        self.assertIn([self.UNMANAGED_ROLE, VIEW_ACTION, "course-v1^*", "allow"], self.enforcer.get_policy())
        self.assertTrue(self.enforcer.enforce(USER_SUBJECT, VIEW_ACTION, COURSE_SCOPE))
        # ...and it is not attributed to any schema source.
        self.assertFalse(AuthzRoleDefinition.objects.filter(role_id="schema_apply_legacy").exists())

    def test_unmanaged_row_survives_an_empty_schema(self):
        """An unmanaged row is preserved even when the applied schema is empty."""
        self.enforcer.add_policy(self.UNMANAGED_ROLE, VIEW_ACTION, "course-v1^*", "allow")
        self.enforcer.load_policy()

        result = self._apply(_document(roles=[]))

        self.assertEqual(result.removed, 0)
        self.assertIn([self.UNMANAGED_ROLE, VIEW_ACTION, "course-v1^*", "allow"], self.enforcer.get_policy())


class TestSchemaApplyFailureIntegration(SchemaApplyIntegrationBase):
    """A failed apply leaves Casbin on the last committed state (ADR 0018 §5).

    ``add_policy`` writes through to the adapter *and* mutates the enforcer's
    in-memory model, so a rollback would otherwise leave this process enforcing
    rows the database never committed.
    """

    def _fail_during_store(self):
        """Make ``_store_sources`` write a row and then fail, like a DB error would."""

        def _store_then_fail(_self, _schema):
            AuthzRoleDefinition.objects.create(
                role_id="schema_apply_half_written",
                display_name="Half written",
                description="",
                scopes=[SCOPE_NAMESPACE],
                hidden=False,
            )
            raise IntegrityError("simulated write failure")

        patcher = mock.patch.object(SchemaApplier, "_store_sources", _store_then_fail)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_failed_apply_rolls_back_every_definition_write(self):
        """A failed apply rolls back every definition row it had started writing."""
        self._fail_during_store()

        with self.assertRaises(IntegrityError):
            self._apply(_document(roles=[_editor_role(("courses.view_course",))]))

        self.assertFalse(AuthzRoleDefinition.objects.filter(role_id="schema_apply_half_written").exists())
        self.assertFalse(AuthzRoleDefinition.objects.filter(role_id="schema_apply_editor").exists())

    def test_failed_apply_leaves_enforcement_on_the_committed_state(self):
        """The reload triggered by cache invalidation drops the uncommitted rows."""
        self._assign_user_to_role()
        self.assertFalse(self.enforcer.enforce(USER_SUBJECT, VIEW_ACTION, COURSE_SCOPE))
        self._fail_during_store()

        with self.assertRaises(IntegrityError):
            self._apply(_document(roles=[_editor_role(("courses.view_course",))]))

        # The apply invalidated the policy cache, so acquiring the enforcer
        # reloads from the database rather than trusting the in-memory model.
        reloaded = AuthzEnforcer.get_enforcer()
        self.assertEqual([row for row in reloaded.get_policy() if row[0] == ROLE_SUBJECT], [])
        self.assertFalse(reloaded.enforce(USER_SUBJECT, VIEW_ACTION, COURSE_SCOPE))


class TestSchemaApplyConcurrencyIntegration(TransactionTestCase):
    """Concurrent applies serialize so the two stores never diverge (ADR 0018 §8, lost-update fix).

    Regression for a lost update between two overlapping applies. When an
    old-schema apply and an updated-schema apply ran at the same time, each
    computed its diff against the same pre-change snapshot and then both wrote,
    leaving the two stores inconsistent: the definition tables kept *both*
    permissions while the Casbin policy kept only the updated one. Apply now
    takes an exclusive row lock (``SELECT ... FOR UPDATE`` on the
    ``PolicyCacheControl`` singleton) as the first statement in its transaction,
    so a second runner blocks until the first commits and then reconciles against
    the already-applied state.

    This runs on a real stack across two database connections, so it needs
    ``TransactionTestCase``: each apply must truly commit for the other
    connection to see it, which the per-test transaction of ``TestCase`` would
    prevent. ``select_for_update`` is a no-op on SQLite (and SQLite serializes
    writers at the file level anyway), so the test is skipped there — it is
    meaningful only on a backend with real row locking (the MySQL environment
    these integration tests target).

    Scope: this proves serialization and the consistent end state of a real
    overlapping race. The individual mechanisms the fix relies on — the lock row
    being created before the transaction opens (fresh Repeatable Read snapshot)
    and the enforcer being reloaded under the lock (fresh in-memory p rows) — are
    asserted deterministically in ``TestApplySerialization`` in
    ``tests/schema/test_apply.py``, which does not depend on backend-specific MVCC
    timing.
    """

    def setUp(self):
        """Start from a clean, committed policy with one permission applied."""
        if not connection.features.has_select_for_update:
            self.skipTest("Backend does not support SELECT ... FOR UPDATE row locking.")

        self.enforcer = AuthzEnforcer.get_enforcer()
        self.enforcer.clear_policy()
        # Seed the starting state both overlapping applies will diff against:
        # the role granting only view_course.
        self._apply_sync(_document(roles=[_editor_role(("courses.view_course",))]))

    def tearDown(self):
        """Leave no policy behind for other integration tests."""
        self.enforcer.clear_policy()

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _apply_sync(*documents, force=False):
        """Compile, render, and apply ``documents`` synchronously (no pause)."""
        schema = SchemaCompiler().compile(list(documents))
        rendered = PolicyRenderer().render(schema)
        return SchemaApplier().apply(rendered, schema, force=force)

    def _p_actions_for_role(self):
        """Return the set of actions the test role grants in the stored policy."""
        self.enforcer.load_policy()
        return {row[1] for row in self.enforcer.get_policy() if row[0] == ROLE_SUBJECT}

    def _definition_actions_for_role(self):
        """Return the set of permission names the role's definition grants."""
        return {
            f"act^{perm.permission.namespace}.{perm.permission.name}"
            for perm in AuthzRolePermission.objects.select_related("permission").filter(
                role__role_id="schema_apply_editor"
            )
        }

    def test_overlapping_applies_serialize_and_leave_consistent_stores(self):
        """A stale apply overlapping an updated apply ends with both stores agreeing.

        This drives the exact window that produced the lost update. The seed
        grants ``view_course``. Thread A applies a schema that *drops*
        ``view_course`` and grants ``manage_tags`` — a real change — and pauses
        with its write done but its transaction *not yet committed*, still
        holding the lock. Thread B then applies a schema granting *both*
        ``view_course`` and ``manage_tags`` while A holds the lock, so B contends
        for the lock before A commits.

        The point is what B must observe once it proceeds: A has removed
        ``view_course``, so B's reconciliation has to re-add it on top of A's
        committed state. B reads the ``p`` rows (via the enforcer) and the
        definition tables (via plain ``SELECT``). Under InnoDB Repeatable Read, a
        read taken before the lock blocks would pin B's snapshot to the pre-A
        state (``view_course`` present, ``manage_tags`` absent); its diff would
        then be computed against stale data and the two stores would diverge.
        Taking the locking read first and reloading the enforcer under the lock
        makes B see A's commit, so both stores end up granting exactly
        ``{view_course, manage_tags}`` and agree with each other.
        """
        a_schema = _document(roles=[_editor_role(("courses.manage_tags",))])
        b_schema = _document(roles=[_editor_role(("courses.view_course", "courses.manage_tags"))])

        order, errors, release_fired = self._run_overlapping_applies(a_schema, b_schema)

        self.assertEqual(errors, {}, f"A worker raised: {errors}")
        self.assertTrue(release_fired, "Thread A never reached its release point")

        # Serialization: B committed only after A committed.
        self.assertIn("a_committed", order)
        self.assertIn("b_committed", order)
        self.assertLess(
            order.index("a_committed"),
            order.index("b_committed"),
            f"B must commit after A; observed order: {order}",
        )

        # Snapshot freshness + cross-store consistency: B reconciled against A's
        # committed state (view_course removed), so B re-added it on top. Both
        # the Casbin policy and the definition tables end up granting exactly
        # {view_course, manage_tags} and agree with each other. A stale pre-A
        # snapshot in B would leave the stores disagreeing.
        expected = {VIEW_ACTION, TAGS_ACTION}
        self.assertEqual(self._p_actions_for_role(), expected)
        self.assertEqual(self._definition_actions_for_role(), expected)
        self.assertEqual(self._p_actions_for_role(), self._definition_actions_for_role())

    def _run_overlapping_applies(self, a_schema, b_schema):
        """Run two applies that overlap on the lock and return their observed timeline.

        Thread A applies ``a_schema`` but pauses after its writes and before
        commit, still inside the locked transaction (``_store_sources`` is the
        last write in ``apply``, so holding there holds the lock with A's change
        written-but-uncommitted). Thread B applies ``b_schema`` and is released
        only once A is parked mid-write, so B is forced to contend for the lock
        while A's change is still uncommitted — the exact window the fix guards.

        Returns:
            tuple: ``(order, errors, release_fired)`` where ``order`` is the list
            of timeline markers, ``errors`` maps worker name to any raised
            exception, and ``release_fired`` is whether A reached its release
            point (a guard against a silently stuck A).
        """
        a_holds_lock_mid_write = threading.Event()
        release_a = threading.Event()
        b_contending = threading.Event()
        order: list[str] = []
        order_lock = threading.Lock()
        errors: dict[str, BaseException] = {}

        def mark(event: str) -> None:
            with order_lock:
                order.append(event)

        applier_a = SchemaApplier()
        real_store_sources = applier_a._store_sources  # pylint: disable=protected-access

        def paused_store_sources(schema):
            real_store_sources(schema)
            mark("a_wrote")
            a_holds_lock_mid_write.set()
            # Wait until B is actively contending for the lock, then hold a touch
            # longer so B is parked on the lock (not merely about to ask for it)
            # before A commits. Bounded so a bug cannot hang the suite.
            b_contending.wait(timeout=10)
            time.sleep(1)
            release_a.set()

        def run_a():
            try:
                with mock.patch.object(applier_a, "_store_sources", side_effect=paused_store_sources):
                    schema = SchemaCompiler().compile([a_schema])
                    applier_a.apply(PolicyRenderer().render(schema), schema)
                mark("a_committed")
            except BaseException as exc:
                errors["a"] = exc
            finally:
                connections.close_all()

        def run_b():
            try:
                a_holds_lock_mid_write.wait(timeout=10)
                b_contending.set()
                self._apply_sync(b_schema)
                mark("b_committed")
            except BaseException as exc:
                errors["b"] = exc
            finally:
                connections.close_all()

        thread_a = threading.Thread(name="apply-A", target=run_a)
        thread_b = threading.Thread(name="apply-B", target=run_b)
        thread_a.start()
        thread_b.start()
        thread_a.join(timeout=25)
        thread_b.join(timeout=25)

        self.assertFalse(thread_a.is_alive(), "Thread A did not finish")
        self.assertFalse(thread_b.is_alive(), "Thread B did not finish")
        return order, errors, release_a.is_set()
