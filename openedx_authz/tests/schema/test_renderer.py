"""Unit tests for the (pure) render step and renderer helper methods."""

import sys
import types
from unittest import mock

from openedx_authz.engine.renderer import PolicyRenderer, SchemaApplier
from openedx_authz.engine.schema.compilation import SchemaCompiler

from .factories import category, make_document, permission, role


def _schema():
    """Build a compiled schema fixture for renderer tests."""
    doc = make_document(
        categories=[category("cat")],
        permissions=[
            permission(name="view_course", cat="cat", scopes=("course-v1",)),
            permission(name="edit_course_content", cat="cat", scopes=("course-v1",)),
        ],
        roles=[
            role(
                rid="course_editor",
                scopes=("course-v1",),
                permissions=("courses.view_course", "courses.edit_course_content"),
            )
        ],
    )
    return SchemaCompiler().compile([doc])


def test_render_emits_one_p_row_per_role_permission_scope():
    rendered = PolicyRenderer().render(_schema())
    assert len(rendered.rows) == 2
    assert all(row.ptype == "p" and row.effect == "allow" for row in rendered.rows)


def test_render_applies_casbin_namespacing():
    rendered = PolicyRenderer().render(_schema())
    row = next(r for r in rendered.rows if r.action == "act^courses.view_course")
    assert row.subject == "role^course_editor"
    assert row.scope == "course-v1^*"
    assert row.as_policy() == ["role^course_editor", "act^courses.view_course", "course-v1^*", "allow"]


def test_render_is_deterministic():
    schema = _schema()
    assert PolicyRenderer().render(schema).rows == PolicyRenderer().render(schema).rows


def test_multiple_scopes_multiply_rows():
    doc = make_document(
        categories=[category("cat")],
        permissions=[permission(name="view_course", cat="cat", scopes=("course-v1", "ccx-v1"))],
        roles=[role(rid="r", scopes=("course-v1", "ccx-v1"), permissions=("courses.view_course",))],
    )
    rendered = PolicyRenderer().render(SchemaCompiler().compile([doc]))
    scopes = {row.scope for row in rendered.rows}
    assert scopes == {"course-v1^*", "ccx-v1^*"}


class TestResolveEnforcer:
    """Cover SchemaApplier._resolve_enforcer both branches."""

    def test_returns_injected_enforcer_without_importing(self):
        """An enforcer passed in is returned as-is (no lazy resolution)."""
        sentinel = object()
        applier = SchemaApplier(enforcer=sentinel)

        # Patch the lazy import target to prove it is never touched.
        with mock.patch("openedx_authz.engine.enforcer.AuthzEnforcer") as authz_enforcer:
            assert applier._resolve_enforcer() is sentinel  # pylint: disable=protected-access
            authz_enforcer.get_enforcer.assert_not_called()

    def test_lazily_resolves_when_enforcer_is_none(self):
        """When no enforcer was injected, it is fetched via AuthzEnforcer and cached."""
        resolved = object()
        applier = SchemaApplier()  # enforcer defaults to None

        with mock.patch("openedx_authz.engine.enforcer.AuthzEnforcer") as authz_enforcer:
            authz_enforcer.get_enforcer.return_value = resolved

            first = applier._resolve_enforcer()  # pylint: disable=protected-access
            second = applier._resolve_enforcer()  # pylint: disable=protected-access

        assert first is resolved
        # Cached after the first resolution: only one lookup despite two calls.
        assert second is resolved
        authz_enforcer.get_enforcer.assert_called_once_with()


class TestEmitAssignmentDeleted:
    """Cover SchemaApplier._emit_assignment_deleted."""

    def test_no_op_when_no_assignments(self):
        """Empty input emits nothing and does not import event machinery."""
        with mock.patch.dict(sys.modules):
            # If the method tried to import openedx_events, a missing stub would
            # raise; the early return means it never gets there.
            SchemaApplier._emit_assignment_deleted([])  # pylint: disable=protected-access

    def test_emits_one_event_per_removed_assignment(self):
        """Each removed (subject, role, scope) triple sends a ROLE_ASSIGNMENT_DELETED."""
        removed = [
            ("user^alice", "role^course_editor", "course-v1^course-v1:Org+C+R"),
            ("user^bob", "role^course_auditor", "course-v1^*"),
        ]

        # Build lazy-import stubs for the modules the method imports internally.
        crum_mod = types.ModuleType("crum")
        crum_mod.get_current_user = lambda: types.SimpleNamespace(id=42)

        role_assignment_data = mock.MagicMock(name="RoleAssignmentEventData")
        events_data = types.ModuleType("openedx_events.authz.data")
        events_data.RoleAssignmentData = role_assignment_data

        signal = mock.MagicMock(name="ROLE_ASSIGNMENT_DELETED")
        events_signals = types.ModuleType("openedx_events.authz.signals")
        events_signals.ROLE_ASSIGNMENT_DELETED = signal

        with mock.patch.dict(
            sys.modules,
            {
                "crum": crum_mod,
                "openedx_events.authz.data": events_data,
                "openedx_events.authz.signals": events_signals,
            },
        ):
            SchemaApplier._emit_assignment_deleted(removed)  # pylint: disable=protected-access

        assert signal.send_event.call_count == 2

        # Verify field mapping for the first emitted event.
        first_event_data = role_assignment_data.call_args_list[0].kwargs
        assert first_event_data["operation"] == "deleted"
        assert first_event_data["subject"] == "user^alice"
        assert first_event_data["role"] == "role^course_editor"
        assert first_event_data["scope"] == "course-v1^course-v1:Org+C+R"
        assert first_event_data["actor_id"] == 42

    def test_actor_id_none_when_no_current_user(self):
        """A missing current user yields actor_id=None on the event."""
        removed = [("user^alice", "role^course_editor", "course-v1^*")]

        crum_mod = types.ModuleType("crum")
        crum_mod.get_current_user = lambda: None

        role_assignment_data = mock.MagicMock(name="RoleAssignmentEventData")
        events_data = types.ModuleType("openedx_events.authz.data")
        events_data.RoleAssignmentData = role_assignment_data

        signal = mock.MagicMock(name="ROLE_ASSIGNMENT_DELETED")
        events_signals = types.ModuleType("openedx_events.authz.signals")
        events_signals.ROLE_ASSIGNMENT_DELETED = signal

        with mock.patch.dict(
            sys.modules,
            {
                "crum": crum_mod,
                "openedx_events.authz.data": events_data,
                "openedx_events.authz.signals": events_signals,
            },
        ):
            SchemaApplier._emit_assignment_deleted(removed)  # pylint: disable=protected-access

        assert role_assignment_data.call_args_list[0].kwargs["actor_id"] is None
