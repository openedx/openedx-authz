"""Permission dependencies through the real enforcer and the built-in schema (ADR 0034 §4, §5)."""

from casbin_adapter.models import CasbinRule
from django.test import TestCase

from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.engine.schema.pipeline import SchemaPipeline
from openedx_authz.models.schema import AuthzPermissionDependency
from openedx_authz.tests.test_utils import (
    AuthzEnforcerTestMixin,
    make_action_key,
    make_role_key,
    make_scope_key,
    make_user_key,
)

# The action-inheritance rows ``authz.policy`` declared before the static schema replaced it.
LEGACY_LIBRARY_G2_ROWS = {
    ("content_libraries.manage_library_tags", "content_libraries.edit_library_content"),
    ("content_libraries.delete_library", "content_libraries.edit_library_content"),
    ("content_libraries.publish_library_content", "content_libraries.edit_library_content"),
    ("content_libraries.edit_library_content", "content_libraries.view_library"),
    ("content_libraries.reuse_library_content", "content_libraries.view_library"),
    ("content_libraries.publish_library_content", "content_libraries.view_library"),
    ("content_libraries.manage_library_team", "content_libraries.view_library_team"),
    ("content_libraries.delete_library_collection", "content_libraries.edit_library_collection"),
    ("content_libraries.create_library_collection", "content_libraries.edit_library_collection"),
    ("content_libraries.edit_library_collection", "content_libraries.view_library"),
}

# One concrete scope per scope type, for assigning roles in the enforcement check.
SCOPES = {
    "lib": make_scope_key("lib", "lib:DependencyOrg:dependency_library"),
    "course-v1": make_scope_key("course-v1", "course-v1:DependencyOrg+Course+Run"),
}


def stored_g2_rows() -> set[tuple[str, str]]:
    """The stored ``g2`` rows, without the ``act^`` prefix."""
    prefix = make_action_key("")
    return {
        (rule.v0.removeprefix(prefix), rule.v1.removeprefix(prefix)) for rule in CasbinRule.objects.filter(ptype="g2")
    }


def seed_legacy_g2_rows() -> None:
    """Store the ``g2`` rows exactly as loading ``authz.policy`` did."""
    for permission_id, depends_on_id in LEGACY_LIBRARY_G2_ROWS:
        CasbinRule.objects.create(ptype="g2", v0=make_action_key(permission_id), v1=make_action_key(depends_on_id))


class TestBuiltInDependencyRows(AuthzEnforcerTestMixin, TestCase):
    """Applying the built-in schema stores the library dependencies as ``g2`` rows."""

    def test_fresh_install_gets_the_legacy_library_g2_rows(self):
        """A database that never loaded ``authz.policy`` gets the same rows it used to declare."""
        SchemaPipeline().apply()

        assert stored_g2_rows() == LEGACY_LIBRARY_G2_ROWS
        assert AuthzPermissionDependency.objects.count() == len(LEGACY_LIBRARY_G2_ROWS)

    def test_rows_from_authz_policy_are_adopted_without_writes(self):
        """An existing installation keeps its ``g2`` rows, and the loader records that it owns them."""
        seed_legacy_g2_rows()

        result = SchemaPipeline().apply()

        assert result.added_action_rows == 0
        assert result.removed_action_rows == 0
        assert CasbinRule.objects.filter(ptype="g2").count() == len(LEGACY_LIBRARY_G2_ROWS)
        assert AuthzPermissionDependency.objects.count() == len(LEGACY_LIBRARY_G2_ROWS)

    def test_reapplying_changes_nothing(self):
        """A second apply of the same schema writes no ``g2`` rows and reports no change."""
        SchemaPipeline().apply()

        result = SchemaPipeline().apply()

        assert result.unchanged is True
        assert stored_g2_rows() == LEGACY_LIBRARY_G2_ROWS

    def test_unmanaged_g2_row_is_kept(self):
        """A ``g2`` row that no schema declares is left in place."""
        CasbinRule.objects.create(ptype="g2", v0=make_action_key("other.edit"), v1=make_action_key("other.view"))

        SchemaPipeline().apply()

        assert ("other.edit", "other.view") in stored_g2_rows()


class TestEnforcementMatchesRolePermissions(AuthzEnforcerTestMixin, TestCase):
    """With ``g2`` rows in place, each built-in role allows exactly the permissions it lists (ADR 0034).

    Every built-in role lists all of its dependencies, so the ``g2`` rows must not grant anything
    a role does not already list.
    """

    @classmethod
    def setUpTestData(cls):
        """Apply the built-in schema once for the class."""
        super().setUpTestData()
        cls.schema = SchemaPipeline().compile()
        SchemaPipeline().apply()

    def test_each_role_allows_exactly_its_listed_permissions(self):
        """Assign each static role in each of its scope types and check every permission for that scope type."""
        enforcer = AuthzEnforcer.get_enforcer()
        mismatches = []
        for role_id, compiled_role in sorted(self.schema.roles.items()):
            role = compiled_role.definition
            for scope_type in role.scopes:
                user = make_user_key(f"user_{role_id}_{scope_type}")
                enforcer.add_grouping_policy(user, make_role_key(role_id), SCOPES[scope_type])
                for permission_id, compiled_permission in sorted(self.schema.permissions.items()):
                    if scope_type not in compiled_permission.definition.scopes:
                        continue
                    allowed = enforcer.enforce(user, make_action_key(permission_id), SCOPES[scope_type])
                    if allowed != (permission_id in role.permissions):
                        mismatches.append((role_id, scope_type, permission_id, allowed))

        assert not mismatches

    def test_g2_rows_grant_the_dependency_to_a_role_that_does_not_list_it(self):
        """A role outside schema validation still gets the permissions its permissions depend on."""
        enforcer = AuthzEnforcer.get_enforcer()
        user, role, scope = make_user_key("db_only_user"), make_role_key("db_only_role"), SCOPES["lib"]
        enforcer.add_policy(role, make_action_key("content_libraries.delete_library"), "lib^*", "allow")
        enforcer.add_grouping_policy(user, role, scope)

        assert enforcer.enforce(user, make_action_key("content_libraries.edit_library_content"), scope)
        assert enforcer.enforce(user, make_action_key("content_libraries.view_library"), scope)
        assert not enforcer.enforce(user, make_action_key("content_libraries.view_library_team"), scope)
