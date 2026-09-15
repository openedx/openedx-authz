"""Tests for the apply/plan reconciliation path (ADR 0018 §2, §5, §6).

Two layers are exercised:

* A fake in-memory enforcer drives the ``p``/``g`` row reconciliation logic
  (add, remove, force-gated assignment removal, idempotency) without Casbin or
  a database.
* A Django ``TestCase`` covers definition/source pruning through
  :meth:`SchemaApplier._store_sources`, confirming the definition tables track
  the compiled schema across successive applies.
"""

from __future__ import annotations

import pytest
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


def _render(*documents):
    return PolicyRenderer().render(SchemaCompiler().compile(list(documents)))


def _editor(perms):
    return _doc(roles=[role(rid="course_editor", scopes=("course-v1",), permissions=perms)])


@pytest.fixture
def _isolated_applier(monkeypatch):
    """Stub DB source storage and cache invalidation for pure enforcer tests.

    These tests assert only on enforcer ``p``/``g`` state, so persistence and
    the Casbin cache are neutralized to keep them fast and DB-free.
    """
    monkeypatch.setattr(SchemaApplier, "_store_sources", lambda self, schema: None)
    monkeypatch.setattr(
        "openedx_authz.engine.enforcer.AuthzEnforcer.invalidate_policy_cache",
        staticmethod(lambda: None),
        raising=False,
    )


@pytest.mark.django_db
@pytest.mark.usefixtures("_isolated_applier")
class TestApplyReconciliation:
    """Enforcer-level add/remove/idempotency behavior."""

    def test_first_apply_adds_all_rows(self):
        rendered = _render(_editor(("courses.view_course", "courses.manage_tags")))
        enforcer = FakeEnforcer()
        applier = SchemaApplier(enforcer=enforcer)

        result = applier.apply(rendered, SchemaCompiler().compile([]), force=False)

        assert result.added == 2
        assert result.removed == 0
        assert len(enforcer.get_policy()) == 2

    def test_reapply_is_idempotent(self):
        rendered = _render(_editor(("courses.view_course", "courses.manage_tags")))
        enforcer = FakeEnforcer()
        applier = SchemaApplier(enforcer=enforcer)
        schema = SchemaCompiler().compile([])

        applier.apply(rendered, schema)
        result = applier.apply(rendered, schema)

        assert result.added == 0
        assert result.removed == 0
        assert result.unchanged is True
        assert len(enforcer.get_policy()) == 2

    def test_removed_permission_prunes_stale_p_row(self):
        # Start with two permissions on the role, then drop one via extension.
        before = _render(_editor(("courses.view_course", "courses.manage_tags")))
        enforcer = FakeEnforcer()
        SchemaApplier(enforcer=enforcer).apply(before, SchemaCompiler().compile([]))
        assert len(enforcer.get_policy()) == 2

        after = _render(
            _editor(("courses.view_course", "courses.manage_tags")),
            _doc(
                name="modx",
                priority=200,
                roles=[],
                categories=[],
                permissions=[],
                role_extensions=[extension("course_editor", remove_permissions=("courses.manage_tags",))],
            ),
        )
        result = SchemaApplier(enforcer=enforcer).apply(after, SchemaCompiler().compile([]))

        assert result.removed == 1
        remaining = {tuple(row) for row in enforcer.get_policy()}
        assert ["role^course_editor", "act^courses.manage_tags", "course-v1^*", "allow"] not in enforcer.get_policy()
        assert ("role^course_editor", "act^courses.view_course", "course-v1^*", "allow") in remaining

    def test_removed_role_without_assignments_is_pruned(self):
        before = _render(_editor(("courses.view_course",)))
        enforcer = FakeEnforcer()
        SchemaApplier(enforcer=enforcer).apply(before, SchemaCompiler().compile([]))

        # Nothing rendered now -> role's p row is stale and removed.
        empty = PolicyRenderer().render(SchemaCompiler().compile([]))
        result = SchemaApplier(enforcer=enforcer).apply(empty, SchemaCompiler().compile([]))

        assert result.removed == 1
        assert enforcer.get_policy() == []


@pytest.mark.django_db
@pytest.mark.usefixtures("_isolated_applier")
class TestForceGate:
    """Removal of a role that still has user assignments is force-gated."""

    def _assigned_enforcer(self):
        """Build an enforcer holding a stored role plus one user assignment to it."""
        rendered = _render(_editor(("courses.view_course",)))
        enforcer = FakeEnforcer()
        SchemaApplier(enforcer=enforcer).apply(rendered, SchemaCompiler().compile([]))
        # A user is assigned the role (g row: [subject, role, scope]).
        enforcer.add_grouping_policy("user^alice", "role^course_editor", "course-v1:OpenedX+DemoX+Demo")
        return enforcer

    def test_blocking_assignment_aborts_without_force(self):
        enforcer = self._assigned_enforcer()
        empty = PolicyRenderer().render(SchemaCompiler().compile([]))

        with pytest.raises(SchemaApplyError):
            SchemaApplier(enforcer=enforcer).apply(empty, SchemaCompiler().compile([]), force=False)

        # No write happened: the p row is still there.
        assert len(enforcer.get_policy()) == 1

    def test_force_removes_role_rows_and_assignments(self):
        enforcer = self._assigned_enforcer()
        empty = PolicyRenderer().render(SchemaCompiler().compile([]))

        result = SchemaApplier(enforcer=enforcer).apply(empty, SchemaCompiler().compile([]), force=True)

        assert result.removed == 1
        assert enforcer.get_policy() == []
        assert enforcer.get_grouping_policy() == []


class DefinitionPruningTests(TestCase):
    """Definition/source tables track the compiled schema across applies."""

    def test_removed_permission_prunes_grant_and_definition(self):
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
