"""Unit tests for the (pure) render step and renderer helper methods.

Covers turning a compiled schema into Casbin ``p`` rows: one row per
role-permission-scope, the ``role^``/``act^``/``^*`` namespacing convention,
deterministic output, and scope fan-out; plus the ``SchemaApplier`` helpers for
enforcer resolution and role-assignment-deleted event emission.
"""

import types
from unittest import mock

from openedx_authz.engine.policy import PolicyStore
from openedx_authz.engine.renderer import PolicyRenderer, SchemaApplier
from openedx_authz.engine.schema.compilation import SchemaCompiler

from .factories import category, make_document, permission, role


class TestPolicyRendering:
    """Rendering a compiled schema into Casbin ``p`` policy rows."""

    @staticmethod
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

    def test_render_emits_one_p_row_per_role_permission_scope(self):
        """Each role-permission-scope combination becomes one allow ``p`` row."""
        rendered = PolicyRenderer().render(self._schema())
        assert len(rendered.rows) == 2
        assert all(row.effect == "allow" for row in rendered.rows)

    def test_render_applies_casbin_namespacing(self):
        """Subjects, actions, and scopes carry their Casbin namespace prefixes."""
        rendered = PolicyRenderer().render(self._schema())
        row = next(r for r in rendered.rows if r.action == "act^courses.view_course")
        assert row.subject == "role^course_editor"
        assert row.scope == "course-v1^*"
        assert row.as_policy() == ["role^course_editor", "act^courses.view_course", "course-v1^*", "allow"]

    def test_render_is_deterministic(self):
        """Rendering the same schema twice yields identical rows."""
        schema = self._schema()
        assert PolicyRenderer().render(schema).rows == PolicyRenderer().render(schema).rows

    def test_multiple_scopes_multiply_rows(self):
        """A permission spanning multiple scopes fans out into one row per scope."""
        doc = make_document(
            categories=[category("cat")],
            permissions=[permission(name="view_course", cat="cat", scopes=("course-v1", "ccx-v1"))],
            roles=[role(rid="r", scopes=("course-v1", "ccx-v1"), permissions=("courses.view_course",))],
        )
        rendered = PolicyRenderer().render(SchemaCompiler().compile([doc]))
        scopes = {row.scope for row in rendered.rows}
        assert scopes == {"course-v1^*", "ccx-v1^*"}


class TestPolicyStoreInjection:
    """``SchemaApplier`` holds only a :class:`PolicyStore`, never the enforcer.

    Enforcer resolution now lives entirely in the store (see
    :mod:`openedx_authz.tests.test_policy`), so the applier just defaults to a
    bare ``PolicyStore()`` or uses the one it is given.
    """

    def test_defaults_to_a_bare_policy_store(self):
        """With no store injected, the applier builds a default ``PolicyStore``."""
        applier = SchemaApplier()

        assert isinstance(applier._policy_store, PolicyStore)  # pylint: disable=protected-access

    def test_uses_the_injected_policy_store(self):
        """An injected store is used as-is, with no enforcer resolution."""
        sentinel = PolicyStore(enforcer=object())
        applier = SchemaApplier(policy_store=sentinel)

        # Patch the enforcer accessor to prove it is never touched at construction.
        with mock.patch("openedx_authz.engine.renderer.AuthzEnforcer") as authz_enforcer:
            assert applier._policy_store is sentinel  # pylint: disable=protected-access
            authz_enforcer.get_enforcer.assert_not_called()


class TestEmitAssignmentDeleted:
    """``SchemaApplier._emit_assignment_deleted``: one event per removed assignment."""

    def test_no_op_when_no_assignments(self):
        """Empty input emits nothing: the signal is never sent."""
        with mock.patch("openedx_authz.engine.renderer.ROLE_ASSIGNMENT_DELETED") as signal:
            SchemaApplier._emit_assignment_deleted([])  # pylint: disable=protected-access
        signal.send_event.assert_not_called()

    def test_emits_one_event_per_removed_assignment(self):
        """Each removed (subject, role, scope) triple sends a ROLE_ASSIGNMENT_DELETED."""
        removed = [
            ("user^alice", "role^course_editor", "course-v1^course-v1:Org+C+R"),
            ("user^bob", "role^course_auditor", "course-v1^*"),
        ]

        with (
            mock.patch(
                "openedx_authz.engine.renderer.get_current_user",
                return_value=types.SimpleNamespace(id=42),
            ),
            mock.patch("openedx_authz.engine.renderer.RoleAssignmentEventData") as role_assignment_data,
            mock.patch("openedx_authz.engine.renderer.ROLE_ASSIGNMENT_DELETED") as signal,
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

        with (
            mock.patch("openedx_authz.engine.renderer.get_current_user", return_value=None),
            mock.patch("openedx_authz.engine.renderer.RoleAssignmentEventData") as role_assignment_data,
            mock.patch("openedx_authz.engine.renderer.ROLE_ASSIGNMENT_DELETED"),
        ):
            SchemaApplier._emit_assignment_deleted(removed)  # pylint: disable=protected-access

        assert role_assignment_data.call_args_list[0].kwargs["actor_id"] is None
