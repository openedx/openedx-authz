"""Unit tests for the (pure) render step.

Covers turning a compiled schema into Casbin ``p`` rows: one row per
role-permission-scope, the ``role^``/``act^``/``^*`` namespacing convention,
deterministic output, and scope fan-out.
"""

from openedx_authz.engine.renderer import PolicyRenderer
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
        assert all(row.ptype == "p" and row.effect == "allow" for row in rendered.rows)

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
