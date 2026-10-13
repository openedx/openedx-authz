"""Tests for the apply/plan reconciliation path (ADR 0018 §2, §5, §6, §8).

Three layers are exercised:

* A fake in-memory enforcer drives the ``p``/``g`` row reconciliation logic
  (add, remove, force-gated assignment removal, idempotency) against real
  definition tables, because pruning is driven by the recorded ownership rather
  than by a raw policy diff (ADR 0025 §6).
* Failure handling: a rolled-back apply must not leave the enforcer's in-memory
  model ahead of the database (ADR 0018 §5).
* A Django ``TestCase`` covers definition/source pruning through
  :meth:`SchemaApplier._store_sources`, confirming the definition tables track
  the compiled schema across successive applies.
"""

from __future__ import annotations

from unittest import mock

import pytest
from django.db import IntegrityError, transaction
from django.test import TestCase

from openedx_authz.engine.policy import PolicyStore
from openedx_authz.engine.renderer import PolicyRenderer, SchemaApplier
from openedx_authz.engine.schema.compilation import SchemaCompiler
from openedx_authz.engine.schema.exceptions import SchemaApplyError
from openedx_authz.models.engine import PolicyCacheControl
from openedx_authz.models.schema import (
    AuthzPermissionCategory,
    AuthzPermissionDefinition,
    AuthzRoleDefinition,
    AuthzRolePermission,
)

from .factories import category, extension, make_document, permission, role

PERMS = [
    permission(name="view_course", cat="cat"),
    permission(name="manage_tags", cat="cat"),
    permission(name="export_course", cat="cat"),
]


def _doc(*, name="core", priority=100, roles=None, permissions=None, categories=None, role_extensions=None):
    return make_document(
        name,
        priority=priority,
        categories=categories if categories is not None else [category("cat")],
        permissions=permissions if permissions is not None else PERMS,
        roles=roles if roles is not None else [],
        role_extensions=role_extensions or [],
    )


class FakeEnforcer:
    """Minimal in-memory stand-in for the Casbin enforcer used by apply/plan.

    Stores ``p`` rows and ``g`` (grouping) rows as lists of string lists, which
    is the shape the real enforcer returns.
    """

    def __init__(self, policies=None, grouping=None):
        self._policies = [list(row) for row in (policies or [])]
        self._grouping = [list(row) for row in (grouping or [])]

    def load_policy(self):
        """No-op reload hook: the fake is already its own in-memory source of truth."""

    def get_policy(self):
        """Return a copy of the stored ``p`` rows."""
        return [list(row) for row in self._policies]

    def get_grouping_policy(self):
        """Return a copy of the stored ``g`` (grouping) rows."""
        return [list(row) for row in self._grouping]

    def add_policy(self, *args):
        """Add a ``p`` row, ignoring exact duplicates. Returns True if added."""
        row = list(args)
        if row not in self._policies:
            self._policies.append(row)
            return True
        return False

    def remove_policy(self, *args):
        """Remove a ``p`` row if present. Returns True if removed."""
        row = list(args)
        if row in self._policies:
            self._policies.remove(row)
            return True
        return False

    def add_grouping_policy(self, *args):
        """Add a ``g`` row, ignoring exact duplicates. Returns True if added."""
        row = list(args)
        if row not in self._grouping:
            self._grouping.append(row)
            return True
        return False

    def remove_grouping_policy(self, *args):
        """Remove a ``g`` row if present. Returns True if removed."""
        row = list(args)
        if row in self._grouping:
            self._grouping.remove(row)
            return True
        return False


def _compile(*documents):
    return SchemaCompiler().compile(list(documents))


def _render(*documents):
    return PolicyRenderer().render(_compile(*documents))


def _editor(perms):
    return _doc(roles=[role(rid="course_editor", scopes=("course-v1",), permissions=perms)])


def _without_manage_tags():
    """An extension that removes ``courses.manage_tags`` from ``course_editor``."""
    return _doc(
        name="modx",
        priority=200,
        roles=[],
        categories=[],
        permissions=[],
        role_extensions=[extension("course_editor", remove_permissions=("courses.manage_tags",))],
    )


@pytest.fixture(name="cache_invalidation")
def cache_invalidation_fixture(monkeypatch):
    """Capture policy-cache invalidation rather than writing a version row.

    Returns the mock so tests can assert *whether* the cache was invalidated,
    which is the observable contract on both the success and failure paths.
    """
    invalidate = mock.Mock(name="invalidate_policy_cache")
    monkeypatch.setattr(
        "openedx_authz.engine.enforcer.AuthzEnforcer.invalidate_policy_cache",
        staticmethod(invalidate),
        raising=False,
    )
    return invalidate


def _apply(enforcer, *documents, force=False):
    """Compile, render and apply one coherent schema.

    Rendering and persistence must come from the *same* compiled schema:
    pruning is driven by the ownership recorded in the definition tables, so a
    render that disagrees with what was stored would leave rows unattributed
    and unprunable.
    """
    schema = _compile(*documents)
    rendered = PolicyRenderer().render(schema)
    return SchemaApplier(policy_store=PolicyStore(enforcer)).apply(rendered, schema, force=force)


@pytest.mark.django_db
@pytest.mark.usefixtures("cache_invalidation")
class TestApplyReconciliation:
    """Enforcer-level add/remove/idempotency behavior."""

    def test_first_apply_adds_all_rows(self):
        """A first apply adds one policy row per rendered grant."""
        enforcer = FakeEnforcer()

        result = _apply(enforcer, _editor(("courses.view_course", "courses.manage_tags")))

        assert result.added == 2
        assert result.removed == 0
        assert len(enforcer.get_policy()) == 2

    def test_reapply_is_idempotent(self):
        """Re-applying the same schema adds and removes nothing."""
        enforcer = FakeEnforcer()
        document = _editor(("courses.view_course", "courses.manage_tags"))

        _apply(enforcer, document)
        result = _apply(enforcer, document)

        assert result.added == 0
        assert result.removed == 0
        assert result.unchanged is True
        assert len(enforcer.get_policy()) == 2

    def test_removed_permission_prunes_stale_p_row(self):
        """Removing a permission prunes its stale policy row, keeping the others."""
        # Start with two permissions on the role, then drop one via extension.
        enforcer = FakeEnforcer()
        base = _editor(("courses.view_course", "courses.manage_tags"))
        _apply(enforcer, base)
        assert len(enforcer.get_policy()) == 2

        result = _apply(enforcer, base, _without_manage_tags())

        assert result.removed == 1
        remaining = {tuple(row) for row in enforcer.get_policy()}
        assert ("role^course_editor", "act^courses.manage_tags", "course-v1^*", "allow") not in remaining
        assert ("role^course_editor", "act^courses.view_course", "course-v1^*", "allow") in remaining

    def test_removed_role_without_assignments_is_pruned(self):
        """A role dropped from the schema is pruned when it has no assignments."""
        enforcer = FakeEnforcer()
        _apply(enforcer, _editor(("courses.view_course",)))

        # Nothing rendered now -> the role's p row is stale and removed.
        result = _apply(enforcer)

        assert result.removed == 1
        assert enforcer.get_policy() == []


@pytest.mark.django_db
@pytest.mark.usefixtures("cache_invalidation")
class TestOwnershipBoundary:
    """Only rows the loader recorded as its own may be pruned (ADR 0025 §6).

    A stored ``p`` row that no schema declares — a legacy policy-file row, an
    administrative fix (ADR 0018 §7), or a row owned by another service — stays
    in place and enforceable, and is never attributed to a schema source.
    """

    UNMANAGED = ("role^legacy_thing", "act^courses.view_course", "course-v1^*", "allow")

    def test_unmanaged_policy_row_is_preserved(self):
        """A policy row no schema owns is left in place by apply."""
        enforcer = FakeEnforcer(policies=[self.UNMANAGED])

        _apply(enforcer, _editor(("courses.view_course",)))

        assert list(self.UNMANAGED) in enforcer.get_policy()

    def test_unmanaged_row_is_not_reported_as_removed(self):
        """An unmanaged row is never counted among the removed rows."""
        enforcer = FakeEnforcer(policies=[self.UNMANAGED])

        result = _apply(enforcer, _editor(("courses.view_course",)))

        assert result.removed == 0

    def test_unmanaged_row_survives_an_empty_schema(self):
        """Even with nothing to render, an unowned row is not ours to delete."""
        enforcer = FakeEnforcer(policies=[self.UNMANAGED])

        result = _apply(enforcer)

        assert result.removed == 0
        assert enforcer.get_policy() == [list(self.UNMANAGED)]

    def test_unmanaged_row_is_not_attributed(self):
        """An unmanaged row gains no definition/source attribution."""
        enforcer = FakeEnforcer(policies=[self.UNMANAGED])

        _apply(enforcer, _editor(("courses.view_course",)))

        assert not AuthzRoleDefinition.objects.filter(role_id="legacy_thing").exists()

    def test_adopts_preexisting_rows_without_definitions(self):
        """ADR 0025 §6: an existing row gains definitions instead of being rewritten.

        This is the realistic first deployment: ``load_policies`` already wrote
        the ``p`` rows and the definition tables are empty. No policy row moves,
        but the definitions are new, so the run is *not* reported as unchanged.
        """
        document = _editor(("courses.view_course",))
        preexisting = [row.as_policy() for row in _render(document).rows]
        enforcer = FakeEnforcer(policies=preexisting)

        result = _apply(enforcer, document)

        assert result.added == 0
        assert result.removed == 0
        assert result.unchanged is False
        assert enforcer.get_policy() == preexisting
        grant = AuthzRolePermission.objects.get()
        assert grant.role.role_id == "course_editor"
        assert grant.sources.count() == 1

    def test_pruning_follows_the_recorded_grant(self):
        """The prune is driven by the grant row, not by the raw policy diff."""
        enforcer = FakeEnforcer()
        base = _editor(("courses.view_course", "courses.manage_tags"))
        _apply(enforcer, base)
        assert AuthzRolePermission.objects.count() == 2

        _apply(enforcer, base, _without_manage_tags())

        assert AuthzRolePermission.objects.count() == 1
        assert len(enforcer.get_policy()) == 1


@pytest.mark.django_db
@pytest.mark.usefixtures("cache_invalidation")
class TestForceGate:
    """Removal of a role that still has user assignments is force-gated."""

    def _assigned_enforcer(self):
        """Build an enforcer holding a stored role plus one user assignment to it."""
        enforcer = FakeEnforcer()
        _apply(enforcer, _editor(("courses.view_course",)))
        # A user is assigned the role (g row: [subject, role, scope]).
        enforcer.add_grouping_policy("user^alice", "role^course_editor", "course-v1:OpenedX+DemoX+Demo")
        return enforcer

    def test_blocking_assignment_aborts_without_force(self, cache_invalidation):
        """Removing a role with a live assignment aborts without ``force``."""
        enforcer = self._assigned_enforcer()
        # Seeding the role in _assigned_enforcer already bumped the cache; only
        # the aborted apply below should be checked, so start from a clean mock.
        cache_invalidation.reset_mock()

        with pytest.raises(SchemaApplyError):
            _apply(enforcer, force=False)

        # No write happened: the p row is still there.
        assert len(enforcer.get_policy()) == 1
        # The force gate raises SchemaApplyError before any mutation, and that
        # branch deliberately skips the cache bump — nothing changed, so forcing
        # a reload would be pointless churn. Pin that so a future change that
        # starts invalidating on the gate path is caught.
        cache_invalidation.assert_not_called()

    def test_force_removes_role_rows_and_assignments(self):
        """With ``force``, the removed role's policy and assignment rows are pruned."""
        enforcer = self._assigned_enforcer()

        result = _apply(enforcer, force=True)

        assert result.removed == 1
        assert enforcer.get_policy() == []
        assert enforcer.get_grouping_policy() == []


@pytest.mark.django_db
class TestApplyFailure:
    """A failed write must not leave Casbin ahead of the database (ADR 0018 §5).

    ``add_policy``/``remove_policy`` mutate the enforcer's in-memory model as
    well as the database, so a rollback would otherwise leave the process
    enforcing rows that were never committed.
    """

    @staticmethod
    def _failing_store(monkeypatch):
        """Write a definition row, then fail, so rollback is observable."""

        def _store_then_fail(self, schema):  # pylint: disable=unused-argument
            AuthzRoleDefinition.objects.create(
                role_id="half_written",
                display_name="Half written",
                description="",
                scopes=["course-v1"],
                hidden=False,
            )
            raise IntegrityError("simulated write failure")

        monkeypatch.setattr(SchemaApplier, "_store_sources", _store_then_fail)

    def test_failure_propagates(self, monkeypatch, cache_invalidation):  # pylint: disable=unused-argument
        """A write failure during apply propagates to the caller."""
        self._failing_store(monkeypatch)

        with pytest.raises(IntegrityError):
            _apply(FakeEnforcer(), _editor(("courses.view_course",)))

    def test_failure_rolls_back_definition_writes(self, monkeypatch, cache_invalidation):  # pylint: disable=unused-argument
        """A failed apply rolls back any definition rows it had written."""
        self._failing_store(monkeypatch)

        with pytest.raises(IntegrityError):
            _apply(FakeEnforcer(), _editor(("courses.view_course",)))

        assert not AuthzRoleDefinition.objects.filter(role_id="half_written").exists()

    def test_failure_invalidates_the_policy_cache(self, monkeypatch, cache_invalidation):
        """The in-memory model kept the rolled-back rows, so force a reload."""
        self._failing_store(monkeypatch)
        enforcer = FakeEnforcer()

        with pytest.raises(IntegrityError):
            _apply(enforcer, _editor(("courses.view_course",)))

        # The fake enforcer models the real divergence: it still holds the row
        # the database rolled back. Invalidating the cache is what makes the
        # next enforcer access reload the committed state.
        assert len(enforcer.get_policy()) == 1
        cache_invalidation.assert_called_once_with()

    def test_successful_apply_invalidates_once_when_rows_change(self, cache_invalidation):
        """A successful apply that changes rows invalidates the policy cache once."""
        _apply(FakeEnforcer(), _editor(("courses.view_course",)))

        cache_invalidation.assert_called_once_with()

    def test_successful_apply_skips_invalidation_when_unchanged(self, cache_invalidation):
        """An apply that changes nothing does not invalidate the policy cache."""
        enforcer = FakeEnforcer()
        document = _editor(("courses.view_course",))
        _apply(enforcer, document)
        cache_invalidation.reset_mock()

        _apply(enforcer, document)

        cache_invalidation.assert_not_called()


class TestDefinitionPruning(TestCase):
    """Definition/source tables track the compiled schema across applies."""

    def test_removed_permission_prunes_grant_and_definition(self):
        """Dropping a permission prunes both its grant and its definition row."""
        applier = SchemaApplier()

        first = SchemaCompiler().compile([_editor(("courses.view_course", "courses.manage_tags"))])
        applier._store_sources(first)  # pylint: disable=protected-access
        editor = AuthzRoleDefinition.objects.get(role_id="course_editor")
        assert editor.role_permissions.count() == 2

        # Drop manage_tags via an extension and remove the permission definition.
        second = SchemaCompiler().compile(
            [
                _doc(
                    roles=[role(rid="course_editor", permissions=("courses.view_course",))],
                    permissions=[permission(name="view_course", cat="cat")],
                )
            ]
        )
        applier._store_sources(second)  # pylint: disable=protected-access

        editor.refresh_from_db()
        assert editor.role_permissions.count() == 1
        assert not AuthzPermissionDefinition.objects.filter(name="manage_tags").exists()
        assert not AuthzPermissionDefinition.objects.filter(name="export_course").exists()

    def test_removed_role_and_category_are_pruned(self):
        """Applying an empty schema prunes every role, grant, permission, and category."""
        applier = SchemaApplier()
        applier._store_sources(  # pylint: disable=protected-access
            SchemaCompiler().compile([_editor(("courses.view_course",))])
        )
        assert AuthzRoleDefinition.objects.filter(role_id="course_editor").exists()

        # Apply an empty schema: everything the previous schema owned is pruned.
        applier._store_sources(SchemaCompiler().compile([]))  # pylint: disable=protected-access

        assert AuthzRoleDefinition.objects.count() == 0
        assert AuthzRolePermission.objects.count() == 0
        assert AuthzPermissionDefinition.objects.count() == 0
        assert AuthzPermissionCategory.objects.count() == 0


@pytest.mark.django_db
@pytest.mark.usefixtures("cache_invalidation")
class TestDefinitionChangeReport:
    """The plan reports definition changes, not just policy rows (ADR 0018 §6).

    Apply syncs the definition tables unconditionally, so a metadata-only edit
    changes stored state while leaving every ``p`` row identical. Reporting only
    rows would tell the operator "unchanged" and then rewrite their metadata.
    """

    @staticmethod
    def _plan(enforcer, *documents):
        schema = _compile(*documents)
        return SchemaApplier(policy_store=PolicyStore(enforcer)).plan(PolicyRenderer().render(schema), schema)

    def test_first_run_reports_every_definition_as_added(self):
        """A first run reports every role, category, permission, and grant as added."""
        plan = self._plan(FakeEnforcer(), _editor(("courses.view_course",)))

        assert plan.roles.added == ["course_editor"]
        assert plan.categories.added == ["cat"]
        assert "courses.view_course" in plan.permissions.added
        assert plan.grants.added == ["course_editor -> courses.view_course @ course-v1"]
        assert plan.unchanged is False

    def test_identical_reapply_reports_no_definition_changes(self):
        """Re-planning an identical schema reports no definition changes."""
        enforcer = FakeEnforcer()
        document = _editor(("courses.view_course",))
        _apply(enforcer, document)

        plan = self._plan(enforcer, document)

        assert plan.definitions_unchanged is True
        assert plan.unchanged is True

    def test_metadata_only_change_is_reported(self):
        """No p row moves, yet the role's display name would be rewritten."""
        enforcer = FakeEnforcer()
        before = _doc(roles=[role(rid="course_editor", permissions=("courses.view_course",))])
        _apply(enforcer, before)

        after = _doc(
            roles=[
                role(
                    rid="course_editor",
                    permissions=("courses.view_course",),
                    display_name="Course author",
                )
            ]
        )
        plan = self._plan(enforcer, after)

        assert not plan.added_rows
        assert not plan.removed_rows
        assert plan.roles.updated == ["course_editor"]
        assert plan.unchanged is False

    def test_hidden_flag_change_is_reported(self):
        """Flipping a role's ``hidden`` flag is reported as an update."""
        enforcer = FakeEnforcer()
        before = _doc(roles=[role(rid="course_editor", permissions=("courses.view_course",))])
        _apply(enforcer, before)

        after = _doc(roles=[role(rid="course_editor", permissions=("courses.view_course",), hidden=True)])
        plan = self._plan(enforcer, after)

        assert plan.roles.updated == ["course_editor"]

    def test_permission_metadata_change_is_reported(self):
        """Editing a permission's display name is reported as an update."""
        enforcer = FakeEnforcer()
        _apply(enforcer, _editor(("courses.view_course",)))

        renamed = _doc(
            roles=[role(rid="course_editor", permissions=("courses.view_course",))],
            permissions=[
                permission(name="view_course", cat="cat", display_name="See course"),
                permission(name="manage_tags", cat="cat"),
                permission(name="export_course", cat="cat"),
            ],
        )
        plan = self._plan(enforcer, renamed)

        assert plan.permissions.updated == ["courses.view_course"]

    def test_category_metadata_change_is_reported(self):
        """Editing a category's display metadata is reported as an update."""
        enforcer = FakeEnforcer()
        _apply(enforcer, _editor(("courses.view_course",)))

        recategorized = _doc(
            roles=[role(rid="course_editor", permissions=("courses.view_course",))],
            categories=[category("cat", display_name="Course content", icon="Article")],
        )
        plan = self._plan(enforcer, recategorized)

        assert plan.categories.updated == ["cat"]

    def test_dropped_definitions_are_reported_as_removed(self):
        """Definitions absent from the new schema are reported as removed."""
        enforcer = FakeEnforcer()
        _apply(enforcer, _editor(("courses.view_course",)))

        plan = self._plan(enforcer)

        assert plan.roles.removed == ["course_editor"]
        assert plan.categories.removed == ["cat"]
        assert plan.grants.removed == ["course_editor -> courses.view_course @ course-v1"]

    def test_grant_change_is_reported_alongside_the_row(self):
        """A removed grant is reported both as a grant change and a removed row."""
        enforcer = FakeEnforcer()
        base = _editor(("courses.view_course", "courses.manage_tags"))
        _apply(enforcer, base)

        plan = self._plan(enforcer, base, _without_manage_tags())

        assert plan.grants.removed == ["course_editor -> courses.manage_tags @ course-v1"]
        assert len(plan.removed_rows) == 1

    def test_plan_without_a_schema_reports_rows_only(self):
        """``plan`` stays usable for row-only comparisons (schema optional)."""
        enforcer = FakeEnforcer()

        plan = SchemaApplier(policy_store=PolicyStore(enforcer)).plan(_render(_editor(("courses.view_course",))))

        assert len(plan.added_rows) == 1
        assert plan.definitions_unchanged is True

    def test_plan_does_not_write(self):
        """Planning is read-only: it writes no policy rows or definitions."""
        enforcer = FakeEnforcer()

        self._plan(enforcer, _editor(("courses.view_course",)))

        assert enforcer.get_policy() == []
        assert AuthzRoleDefinition.objects.count() == 0


@pytest.mark.django_db
@pytest.mark.usefixtures("cache_invalidation")
class TestApplySerialization:
    """Apply serializes concurrent runs with an exclusive lock (ADR 0018 §8, lost-update fix).

    Two concurrent ``load_authz_schema`` runs used to each diff against the same
    starting snapshot and both write, leaving the Casbin ``p`` rows and the
    definition tables disagreeing. Apply now takes ``PolicyCacheControl.lock``
    (a ``SELECT ... FOR UPDATE`` on the singleton row) as the first statement
    inside its transaction, so a second runner blocks until the first commits
    and then reads the already-applied state.

    These are deterministic, single-process assertions on the *mechanism* the
    fix depends on — complementing the real two-connection race in
    ``tests/integration/test_schema_apply.py``. They assert the lock is taken,
    that it is taken before any state is read and held inside the transaction,
    that the lock row is created before the transaction opens (so the locking
    read is the transaction's first read, which is what keeps the Repeatable
    Read snapshot fresh), and that the enforcer is reloaded under the lock before
    the p-row read (so the in-memory model cannot leave the read stale).
    """

    def test_apply_takes_the_lock(self):
        """A normal apply acquires the serialization lock exactly once."""
        enforcer = FakeEnforcer()

        with mock.patch(
            "openedx_authz.engine.renderer.PolicyCacheControl.lock",
            wraps=PolicyCacheControl.lock,
        ) as lock:
            _apply(enforcer, _editor(("courses.view_course",)))

        lock.assert_called_once_with()

    def test_lock_is_acquired_before_state_is_read(self):
        """The lock is taken before plan() reads the stored policy.

        Reading first and locking second would reintroduce the race: the diff
        would be computed against a snapshot another apply could change before
        this one writes. The order is the whole point of the fix.
        """
        enforcer = FakeEnforcer()
        calls: list[str] = []
        real_lock = PolicyCacheControl.lock

        def record_lock():
            calls.append("lock")
            return real_lock()

        original_get_policy = enforcer.get_policy

        def record_read():
            calls.append("read")
            return original_get_policy()

        with (
            mock.patch(
                "openedx_authz.engine.renderer.PolicyCacheControl.lock",
                side_effect=record_lock,
            ),
            mock.patch.object(enforcer, "get_policy", side_effect=record_read),
        ):
            _apply(enforcer, _editor(("courses.view_course",)))

        assert calls[0] == "lock"
        assert "read" in calls

    def test_lock_is_acquired_inside_a_transaction(self):
        """The lock is taken while a transaction is open, so it serializes writers.

        A row lock only holds for the life of its transaction; if apply took it
        outside ``transaction.atomic()`` it would release immediately and serialize
        nothing.
        """
        enforcer = FakeEnforcer()
        in_atomic_block: list[bool] = []
        real_lock = PolicyCacheControl.lock

        def record_lock():
            in_atomic_block.append(transaction.get_connection().in_atomic_block)
            return real_lock()

        with mock.patch(
            "openedx_authz.engine.renderer.PolicyCacheControl.lock",
            side_effect=record_lock,
        ):
            _apply(enforcer, _editor(("courses.view_course",)))

        assert in_atomic_block == [True]

    def test_lock_row_is_created_before_the_transaction_opens(self):
        """ensure_exists() runs outside the apply transaction, before the lock.

        Creating the lock row inside the apply transaction would make its
        SELECT/INSERT the transaction's first read and, under InnoDB Repeatable
        Read, pin the consistent-read snapshot before the lock is taken — the
        post-lock reads would then see stale data. ensure_exists() must therefore
        run (and commit) *before* ``transaction.atomic()`` opens, so the locking
        read in lock() is the transaction's genuinely first read.
        """
        enforcer = FakeEnforcer()
        events: list[tuple[str, int]] = []
        real_lock = PolicyCacheControl.lock
        real_ensure = PolicyCacheControl.ensure_exists

        def atomic_depth() -> int:
            # Number of open atomic blocks on this connection. The test harness
            # wraps the test in one, so apply() opening its own block increments
            # this; comparing the depth at ensure_exists vs lock proves apply's
            # transaction opened *between* them.
            return len(transaction.get_connection().atomic_blocks)

        def record_ensure():
            events.append(("ensure_exists", atomic_depth()))
            return real_ensure()

        def record_lock():
            events.append(("lock", atomic_depth()))
            return real_lock()

        with (
            mock.patch(
                "openedx_authz.engine.renderer.PolicyCacheControl.ensure_exists",
                side_effect=record_ensure,
            ),
            mock.patch(
                "openedx_authz.engine.renderer.PolicyCacheControl.lock",
                side_effect=record_lock,
            ),
        ):
            _apply(enforcer, _editor(("courses.view_course",)))

        # ensure_exists runs first; apply then opens its own atomic block before
        # taking the lock, so lock sees a strictly deeper nesting. That ordering
        # is what keeps the lock creation out of the snapshot-pinning transaction.
        assert [name for name, _ in events] == ["ensure_exists", "lock"]
        ensure_depth = events[0][1]
        lock_depth = events[1][1]
        assert lock_depth > ensure_depth

    def test_enforcer_is_reloaded_under_the_lock_before_state_is_read(self):
        """apply() reloads the enforcer after the lock and before plan() reads p rows.

        The lock makes the *database* current, but the enforcer's in-memory model
        is version-gated and the version bump happens after the transaction, so
        without an explicit reload plan() could diff against a prior run's
        in-memory rows. The reload must land after the lock (so it reads the
        committed state the lock exposed) and before the p-row read in plan().
        """
        enforcer = FakeEnforcer()
        calls: list[str] = []
        real_lock = PolicyCacheControl.lock

        def record_lock():
            calls.append("lock")
            return real_lock()

        original_load = enforcer.load_policy
        original_get_policy = enforcer.get_policy

        def record_reload():
            calls.append("reload")
            return original_load()

        def record_get_policy():
            calls.append("get_policy")
            return original_get_policy()

        with (
            mock.patch(
                "openedx_authz.engine.renderer.PolicyCacheControl.lock",
                side_effect=record_lock,
            ),
            mock.patch.object(enforcer, "load_policy", side_effect=record_reload),
            mock.patch.object(enforcer, "get_policy", side_effect=record_get_policy),
        ):
            _apply(enforcer, _editor(("courses.view_course",)))

        # Order: take the lock, reload the enforcer, then read p rows in plan().
        assert calls.index("lock") < calls.index("reload")
        assert calls.index("reload") < calls.index("get_policy")

    @staticmethod
    def _atomic_depth() -> int:
        """Open atomic-block count on the default connection.

        The test harness wraps each test in one atomic block, so apply() opening
        its own increments this. Comparing the depth at a point of interest
        against the baseline tells whether that point ran inside apply's
        transaction (deeper) or after it closed (back at baseline).
        """
        return len(transaction.get_connection().atomic_blocks)

    def test_cache_version_bump_commits_inside_the_transaction(self):
        """On a change, the version bump runs inside the apply transaction.

        If it ran after the transaction (as it once did), the policy rows would
        be committed and visible while the version still read old, so a
        concurrent enforcer would skip its reload and serve stale policy for that
        window. Bumping inside the transaction makes the version change commit
        atomically with the rows, closing that reader window.
        """
        enforcer = FakeEnforcer()
        baseline = self._atomic_depth()
        depth_at_bump: list[int] = []

        def record_invalidate():
            depth_at_bump.append(self._atomic_depth())

        with mock.patch(
            "openedx_authz.engine.renderer.AuthzEnforcer.invalidate_policy_cache",
            side_effect=record_invalidate,
        ):
            _apply(enforcer, _editor(("courses.view_course",)))

        # Exactly one bump on the success path, at a deeper nesting than the
        # baseline — i.e. inside apply's own still-open transaction.
        assert len(depth_at_bump) == 1
        assert depth_at_bump[0] > baseline

    def test_failed_apply_bumps_cache_version_after_rollback(self):
        """On failure the bump runs *outside* the rolled-back transaction.

        A bump inside the transaction would roll back with it, leaving the
        process enforcing the in-memory rows the database discarded. The failure
        path must bump after rollback so the new version actually commits and the
        next enforcer access reloads the committed (pre-apply) state.
        """
        enforcer = FakeEnforcer()
        baseline = self._atomic_depth()
        depth_at_bump: list[int] = []

        def failing_store(_self, _schema):
            raise IntegrityError("simulated write failure")

        def record_invalidate():
            depth_at_bump.append(self._atomic_depth())

        with (
            mock.patch.object(SchemaApplier, "_store_sources", failing_store),
            mock.patch(
                "openedx_authz.engine.renderer.AuthzEnforcer.invalidate_policy_cache",
                side_effect=record_invalidate,
            ),
            pytest.raises(IntegrityError),
        ):
            _apply(enforcer, _editor(("courses.view_course",)))

        # One bump, back at the baseline nesting — apply's transaction had already
        # closed (rolled back), so the bump commits rather than rolling back too.
        assert len(depth_at_bump) == 1
        assert depth_at_bump[0] == baseline
