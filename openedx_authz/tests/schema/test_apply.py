"""Tests for the apply/plan reconciliation path (ADR 0018 §2, §5, §6).

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
from django.db import IntegrityError
from django.test import TestCase

from openedx_authz.engine.renderer import PolicyRenderer, SchemaApplier
from openedx_authz.engine.schema.compilation import SchemaCompiler
from openedx_authz.engine.schema.exceptions import SchemaApplyError
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
    return SchemaApplier(enforcer=enforcer).apply(rendered, schema, force=force)


@pytest.mark.django_db
@pytest.mark.usefixtures("cache_invalidation")
class TestApplyReconciliation:
    """Enforcer-level add/remove/idempotency behavior."""

    def test_first_apply_adds_all_rows(self):
        enforcer = FakeEnforcer()

        result = _apply(enforcer, _editor(("courses.view_course", "courses.manage_tags")))

        assert result.added == 2
        assert result.removed == 0
        assert len(enforcer.get_policy()) == 2

    def test_reapply_is_idempotent(self):
        enforcer = FakeEnforcer()
        document = _editor(("courses.view_course", "courses.manage_tags"))

        _apply(enforcer, document)
        result = _apply(enforcer, document)

        assert result.added == 0
        assert result.removed == 0
        assert result.unchanged is True
        assert len(enforcer.get_policy()) == 2

    def test_removed_permission_prunes_stale_p_row(self):
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
        enforcer = FakeEnforcer(policies=[self.UNMANAGED])

        _apply(enforcer, _editor(("courses.view_course",)))

        assert list(self.UNMANAGED) in enforcer.get_policy()

    def test_unmanaged_row_is_not_reported_as_removed(self):
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

    def test_blocking_assignment_aborts_without_force(self):
        enforcer = self._assigned_enforcer()

        with pytest.raises(SchemaApplyError):
            _apply(enforcer, force=False)

        # No write happened: the p row is still there.
        assert len(enforcer.get_policy()) == 1

    def test_force_removes_role_rows_and_assignments(self):
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
        self._failing_store(monkeypatch)

        with pytest.raises(IntegrityError):
            _apply(FakeEnforcer(), _editor(("courses.view_course",)))

    def test_failure_rolls_back_definition_writes(self, monkeypatch, cache_invalidation):  # pylint: disable=unused-argument
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
        _apply(FakeEnforcer(), _editor(("courses.view_course",)))

        cache_invalidation.assert_called_once_with()

    def test_successful_apply_skips_invalidation_when_unchanged(self, cache_invalidation):
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
        return SchemaApplier(enforcer=enforcer).plan(PolicyRenderer().render(schema), schema)

    def test_first_run_reports_every_definition_as_added(self):
        plan = self._plan(FakeEnforcer(), _editor(("courses.view_course",)))

        assert plan.roles.added == ["course_editor"]
        assert plan.categories.added == ["cat"]
        assert "courses.view_course" in plan.permissions.added
        assert plan.grants.added == ["course_editor -> courses.view_course @ course-v1"]
        assert plan.unchanged is False

    def test_identical_reapply_reports_no_definition_changes(self):
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
        enforcer = FakeEnforcer()
        before = _doc(roles=[role(rid="course_editor", permissions=("courses.view_course",))])
        _apply(enforcer, before)

        after = _doc(roles=[role(rid="course_editor", permissions=("courses.view_course",), hidden=True)])
        plan = self._plan(enforcer, after)

        assert plan.roles.updated == ["course_editor"]

    def test_permission_metadata_change_is_reported(self):
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
        enforcer = FakeEnforcer()
        _apply(enforcer, _editor(("courses.view_course",)))

        recategorized = _doc(
            roles=[role(rid="course_editor", permissions=("courses.view_course",))],
            categories=[category("cat", display_name="Course content", icon="Article")],
        )
        plan = self._plan(enforcer, recategorized)

        assert plan.categories.updated == ["cat"]

    def test_dropped_definitions_are_reported_as_removed(self):
        enforcer = FakeEnforcer()
        _apply(enforcer, _editor(("courses.view_course",)))

        plan = self._plan(enforcer)

        assert plan.roles.removed == ["course_editor"]
        assert plan.categories.removed == ["cat"]
        assert plan.grants.removed == ["course_editor -> courses.view_course @ course-v1"]

    def test_grant_change_is_reported_alongside_the_row(self):
        enforcer = FakeEnforcer()
        base = _editor(("courses.view_course", "courses.manage_tags"))
        _apply(enforcer, base)

        plan = self._plan(enforcer, base, _without_manage_tags())

        assert plan.grants.removed == ["course_editor -> courses.manage_tags @ course-v1"]
        assert len(plan.removed_rows) == 1

    def test_plan_without_a_schema_reports_rows_only(self):
        """``plan`` stays usable for row-only comparisons (schema optional)."""
        enforcer = FakeEnforcer()

        plan = SchemaApplier(enforcer=enforcer).plan(_render(_editor(("courses.view_course",))))

        assert len(plan.added_rows) == 1
        assert plan.definitions_unchanged is True

    def test_plan_does_not_write(self):
        enforcer = FakeEnforcer()

        self._plan(enforcer, _editor(("courses.view_course",)))

        assert enforcer.get_policy() == []
        assert AuthzRoleDefinition.objects.count() == 0
