"""Test cases for creating, editing and removing custom roles (ADR 0035).

The role operations run against the real enforcer and the real definition tables, loaded from the
built-in authorization schema, and check the effect on enforcement as well as on the stored rows.
"""

from collections.abc import Sequence
from datetime import timedelta
from unittest.mock import patch

from casbin_adapter.models import CasbinRule
from ddt import data, ddt, unpack
from django.contrib.auth import get_user_model
from django.db.models import QuerySet
from django.test import TestCase

from openedx_authz.api.catalog import get_role_catalog
from openedx_authz.api.custom_roles import (
    build_custom_role_id,
    create_custom_role,
    remove_custom_role,
    slugify_role_name,
    update_custom_role,
)
from openedx_authz.api.data import RoleData, ScopeData, SubjectData
from openedx_authz.api.exceptions import (
    CustomRoleHasAssignmentsError,
    CustomRoleNameTakenError,
    CustomRoleNotFoundError,
    InvalidCustomRoleError,
    StaticRoleError,
)
from openedx_authz.api.roles import assign_role_to_subject_in_scope
from openedx_authz.constants import CUSTOM_ROLE_ID_MAX_LENGTH, DefinitionKind
from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.engine.policy import PolicyRow, PolicyStore
from openedx_authz.engine.schema.pipeline import SchemaPipeline
from openedx_authz.models.core import ExtendedCasbinRule
from openedx_authz.models.engine import PolicyCacheControl
from openedx_authz.models.schema import AuthzPermissionDefinition, AuthzRoleDefinition, AuthzRolePermission
from openedx_authz.tests.test_utils import (
    AuthzEnforcerTestMixin,
    make_action_key,
    make_library_key,
    make_role_key,
    make_user_key,
)

VIEW_LIBRARY = "content_libraries.view_library"
EDIT_LIBRARY_CONTENT = "content_libraries.edit_library_content"
VIEW_LIBRARY_TEAM = "content_libraries.view_library_team"
VIEW_COURSE = "courses.view_course"
HIDDEN_CATEGORY_PERMISSION = "courses.legacy_beta_tester_permissions"
LIBRARY_SCOPE_TYPE = "lib"
COURSE_SCOPE_TYPE = "course-v1"
LIBRARY = make_library_key("lib:UnitTest:designer")
ALICE = make_user_key("alice")

User = get_user_model()


@ddt
class TestSlugifyRoleName(TestCase):
    """The display name is converted with the standard library only."""

    @data(
        ("Course Designer", "course_designer"),
        ("Diseñador de cursos", "disenador_de_cursos"),
        ("  --Hello,   World!!  ", "hello_world"),
        ("Ünïcödé 2024", "unicode_2024"),
        ("日本語", ""),
    )
    @unpack
    def test_conversion(self, display_name, expected):
        """Accents are dropped, runs of other characters become one underscore, and the ends are trimmed."""
        self.assertEqual(slugify_role_name(display_name), expected)


@ddt
class TestBuildCustomRoleId(TestCase):
    """IDs get the reserved prefix, stay unique and fit the maximum length."""

    @data(
        ("Course Designer", set(), "custom_course_designer"),
        ("Course Designer", {"custom_course_designer"}, "custom_course_designer_2"),
        ("Course Designer", {"custom_course_designer", "custom_course_designer_2"}, "custom_course_designer_3"),
        ("Diseñador de cursos", set(), "custom_disenador_de_cursos"),
        ("日本語", set(), "custom_role"),
        ("Role", {"custom_role"}, "custom_role_2"),
    )
    @unpack
    def test_examples(self, display_name, taken_ids, expected):
        """The first free ID is returned, with the suffix starting at 2."""
        self.assertEqual(build_custom_role_id(display_name, taken_ids), expected)

    def test_long_name_is_cut_to_the_maximum_length(self):
        """A long name is cut so the ID has exactly the maximum length."""
        role_id = build_custom_role_id("a" * 100, set())

        self.assertEqual(role_id, "custom_" + "a" * (CUSTOM_ROLE_ID_MAX_LENGTH - len("custom_")))

    def test_suffix_still_fits_after_the_cut(self):
        """When the cut ID is taken, the name is cut further to leave room for the suffix."""
        taken = {build_custom_role_id("a" * 100, set())}

        role_id = build_custom_role_id("a" * 100, taken)

        self.assertEqual(len(role_id), CUSTOM_ROLE_ID_MAX_LENGTH)
        self.assertTrue(role_id.endswith("_2"))
        self.assertNotIn(role_id, taken)

    def test_underscores_left_at_the_end_of_the_cut_are_dropped(self):
        """A cut that lands right after an underscore does not leave it at the end."""
        role_id = build_custom_role_id("a" * 56 + " " + "b" * 10, set())

        self.assertEqual(role_id, "custom_" + "a" * 56)


class CustomRoleTestCase(AuthzEnforcerTestMixin, TestCase):
    """Store the built-in definitions once for the whole class and give each test a fresh enforcer."""

    @classmethod
    def setUpTestData(cls) -> None:
        """Apply the built-in schema, which stores the definitions and their policy rows, and create Alice."""
        super().setUpTestData()
        SchemaPipeline().apply()
        User.objects.create(username="alice")

    def setUp(self) -> None:
        """Start from an enforcer loaded with the stored policy."""
        super().setUp()
        self.enforcer = AuthzEnforcer.get_enforcer()

    def create_role(
        self, display_name: str = "Designer", permissions: Sequence[str] = (VIEW_LIBRARY,)
    ) -> AuthzRoleDefinition:
        """Create a library custom role with the given permissions."""
        return create_custom_role(display_name, "", LIBRARY_SCOPE_TYPE, permissions)

    def assign(self, role: AuthzRoleDefinition) -> bool:
        """Assign the role to Alice in the test library through the assignment API."""
        return assign_role_to_subject_in_scope(
            SubjectData(namespaced_key=ALICE),
            RoleData(external_key=role.role_id),
            ScopeData(namespaced_key=LIBRARY),
        )

    def is_allowed(self, permission: str) -> bool:
        """Whether Alice may use the permission in the test library."""
        return AuthzEnforcer.get_enforcer().enforce(ALICE, make_action_key(permission), LIBRARY)

    @staticmethod
    def stored_policy_rows(role_id: str) -> QuerySet:
        """The ``p`` rows stored in the database for a role."""
        return CasbinRule.objects.filter(ptype="p", v0=make_role_key(role_id))


@ddt
class TestCreateCustomRole(CustomRoleTestCase):
    """Creating a custom role stores its definition, grants and policy rows together."""

    def test_stores_the_definition(self):
        """The role is a visible, custom role limited to the requested scope type."""
        role = create_custom_role("Course Designer", "Designs courses", LIBRARY_SCOPE_TYPE, [VIEW_LIBRARY])

        stored = AuthzRoleDefinition.objects.get(role_id="custom_course_designer")
        self.assertEqual(stored.pk, role.pk)
        self.assertEqual(stored.display_name, "Course Designer")
        self.assertEqual(stored.description, "Designs courses")
        self.assertEqual(stored.scopes, [LIBRARY_SCOPE_TYPE])
        self.assertEqual(stored.definition_kind, DefinitionKind.USER_DEFINED.value)
        self.assertFalse(stored.hidden)
        self.assertIsNone(stored.removed_at)
        self.assertEqual(stored.sources.count(), 0)

    def test_stores_one_grant_and_policy_row_per_permission(self):
        """Each permission becomes a grant row and the matching Casbin ``p`` row."""
        role = self.create_role(permissions=[VIEW_LIBRARY, EDIT_LIBRARY_CONTENT])

        grants = AuthzRolePermission.objects.filter(role=role)
        self.assertEqual(
            sorted(grant.permission.identifier for grant in grants), sorted([VIEW_LIBRARY, EDIT_LIBRARY_CONTENT])
        )
        self.assertEqual(
            sorted(self.stored_policy_rows(role.role_id).values_list("v1", "v2")),
            sorted(
                [
                    (make_action_key(VIEW_LIBRARY), "lib^*"),
                    (make_action_key(EDIT_LIBRARY_CONTENT), "lib^*"),
                ]
            ),
        )

    def test_holders_get_exactly_the_granted_permissions(self):
        """A user holding the new role is allowed what it grants and nothing else."""
        role = self.create_role(permissions=[VIEW_LIBRARY])
        self.assign(role)

        self.assertTrue(self.is_allowed(VIEW_LIBRARY))
        self.assertFalse(self.is_allowed(EDIT_LIBRARY_CONTENT))

    def test_duplicate_permissions_are_granted_once(self):
        """Repeating a permission in the request does not create two grants."""
        role = self.create_role(permissions=[VIEW_LIBRARY, VIEW_LIBRARY])

        self.assertEqual(AuthzRolePermission.objects.filter(role=role).count(), 1)

    def test_surrounding_whitespace_is_dropped_from_the_name(self):
        """The name is stored, and its ID built, without the whitespace around it."""
        role = self.create_role("  Designer \t")

        role.refresh_from_db()
        self.assertEqual(role.display_name, "Designer")
        self.assertEqual(role.role_id, "custom_designer")

    def test_name_that_converts_to_a_taken_id_gets_a_new_id(self):
        """Two different names that convert to the same ID get the next free ID."""
        first = self.create_role("Course Designer")
        second = self.create_role("Course-Designer")

        self.assertEqual(first.role_id, "custom_course_designer")
        self.assertEqual(second.role_id, "custom_course_designer_2")

    @data("Designer", "DESIGNER", " Designer ", "Library Admin")
    def test_name_taken_by_an_active_role_is_rejected(self, display_name):
        """A name used by another role, custom or static, is rejected ignoring case and surrounding whitespace."""
        self.create_role("Designer")
        policy_before = self.enforcer.get_policy()

        with self.assertRaises(CustomRoleNameTakenError):
            self.create_role(display_name)

        self.assertEqual(AuthzRoleDefinition.objects.user_defined().count(), 1)
        self.assertEqual(self.enforcer.get_policy(), policy_before)

    def test_role_appears_in_the_catalog_as_user_defined(self):
        """The catalog lists the role with the stored definition kind and its permissions."""
        role = self.create_role(permissions=[VIEW_LIBRARY])

        listed = {item["role"]: item for item in get_role_catalog([LIBRARY_SCOPE_TYPE])}[role.role_id]

        self.assertEqual(listed["definition_kind"], DefinitionKind.USER_DEFINED.value)
        self.assertEqual(listed["permissions"], [VIEW_LIBRARY])

    @data(
        ({"display_name": "   "},),
        ({"display_name": "x" * 256},),
        ({"permissions": []},),
        ({"permissions": ["content_libraries.does_not_exist"]},),
        ({"permissions": [VIEW_COURSE]},),
        ({"display_name": None},),
        ({"description": None},),
        ({"scope_type": None},),
        ({"permissions": None},),
        ({"permissions": [None]},),
    )
    @unpack
    def test_rejected_requests_change_nothing(self, overrides):
        """An invalid argument raises before a row or policy line is written."""
        arguments = {
            "display_name": "Designer",
            "description": "",
            "scope_type": LIBRARY_SCOPE_TYPE,
            "permissions": [VIEW_LIBRARY],
            **overrides,
        }
        policy_before = self.enforcer.get_policy()

        with self.assertRaises(InvalidCustomRoleError):
            create_custom_role(**arguments)

        self.assertFalse(AuthzRoleDefinition.objects.user_defined().exists())
        self.assertEqual(self.enforcer.get_policy(), policy_before)

    def test_single_permission_string_is_rejected_as_a_whole(self):
        """A bare string is reported as the wrong type, not split into one unknown ID per character."""
        with self.assertRaisesRegex(InvalidCustomRoleError, "must be a list of permission ID strings"):
            create_custom_role("Designer", "", LIBRARY_SCOPE_TYPE, VIEW_LIBRARY)

    def test_permission_in_a_hidden_category_is_rejected(self):
        """Permissions of a hidden category are reserved for static roles."""
        with self.assertRaisesRegex(InvalidCustomRoleError, HIDDEN_CATEGORY_PERMISSION):
            create_custom_role("Designer", "", COURSE_SCOPE_TYPE, [VIEW_COURSE, HIDDEN_CATEGORY_PERMISSION])

        self.assertFalse(AuthzRoleDefinition.objects.user_defined().exists())

    def test_hidden_permission_is_rejected(self):
        """A permission marked hidden is reserved for static roles."""
        AuthzPermissionDefinition.objects.with_identifiers([EDIT_LIBRARY_CONTENT]).update(hidden=True)

        with self.assertRaisesRegex(InvalidCustomRoleError, EDIT_LIBRARY_CONTENT):
            self.create_role(permissions=[VIEW_LIBRARY, EDIT_LIBRARY_CONTENT])

        self.assertFalse(AuthzRoleDefinition.objects.user_defined().exists())

    def test_failure_while_writing_policy_rolls_everything_back(self):
        """A failure after the first policy row leaves no definition, grant or policy row behind."""
        real_add = PolicyStore.add_policy_row
        written = []

        def fail_on_second_row(store: PolicyStore, row: PolicyRow) -> bool:
            """Write the first policy row and fail on the next one."""
            if written:
                raise RuntimeError("simulated failure")
            written.append(row)
            return real_add(store, row)

        version_before = PolicyCacheControl.get().version
        with patch.object(PolicyStore, "add_policy_row", autospec=True, side_effect=fail_on_second_row):
            with self.assertRaises(RuntimeError):
                self.create_role(permissions=[VIEW_LIBRARY, EDIT_LIBRARY_CONTENT])

        self.assertEqual(len(written), 1)
        self.assertFalse(AuthzRoleDefinition.objects.user_defined().exists())
        self.assertFalse(AuthzRolePermission.objects.user_defined().exists())
        self.assertFalse(self.stored_policy_rows("custom_designer").exists())
        self.assertNotEqual(PolicyCacheControl.get().version, version_before)

    def test_takes_the_policy_write_lock(self):
        """Creating a role excludes concurrent schema deployments and other role changes."""
        with patch("openedx_authz.engine.policy.PolicyCacheControl.lock", wraps=PolicyCacheControl.lock) as lock:
            self.create_role()

        lock.assert_called_once_with()


@ddt
class TestUpdateCustomRole(CustomRoleTestCase):
    """Editing a role changes only what differs and reaches its holders at once."""

    def test_added_and_dropped_permissions_reach_holders_immediately(self):
        """Holders gain the added permission and lose the dropped one without reassigning the role."""
        role = self.create_role(permissions=[VIEW_LIBRARY])
        self.assign(role)

        update_custom_role(role.role_id, permissions=[VIEW_LIBRARY_TEAM])

        self.assertTrue(self.is_allowed(VIEW_LIBRARY_TEAM))
        self.assertFalse(self.is_allowed(VIEW_LIBRARY))
        self.assertEqual(
            list(AuthzRolePermission.objects.filter(role=role).values_list("permission__name", flat=True)),
            ["view_library_team"],
        )
        self.assertEqual(
            list(self.stored_policy_rows(role.role_id).values_list("v1", flat=True)),
            [make_action_key(VIEW_LIBRARY_TEAM)],
        )

    def test_kept_permissions_keep_their_grants(self):
        """A permission that stays is not deleted and recreated."""
        role = self.create_role(permissions=[VIEW_LIBRARY])
        kept = AuthzRolePermission.objects.get(role=role)

        update_custom_role(role.role_id, permissions=[VIEW_LIBRARY, EDIT_LIBRARY_CONTENT])

        self.assertTrue(AuthzRolePermission.objects.filter(pk=kept.pk).exists())
        self.assertEqual(AuthzRolePermission.objects.filter(role=role).count(), 2)

    def test_description_only_leaves_permissions_alone(self):
        """Changing the description does not touch the grants or the policy."""
        role = self.create_role()
        policy_before = self.enforcer.get_policy()

        updated = update_custom_role(role.role_id, description="New description")

        self.assertEqual(AuthzRoleDefinition.objects.get(pk=role.pk).description, "New description")
        self.assertEqual(updated.description, "New description")
        self.assertEqual(self.enforcer.get_policy(), policy_before)

    @data({"description": "New description"}, {"permissions": [EDIT_LIBRARY_CONTENT]})
    def test_any_edit_sets_updated_at(self, changes):
        """Editing only the description or only the permissions both record when the role changed."""
        role = self.create_role(permissions=[VIEW_LIBRARY])
        later = role.updated_at + timedelta(days=1)

        with patch("django.utils.timezone.now", return_value=later):
            update_custom_role(role.role_id, **changes)

        self.assertEqual(AuthzRoleDefinition.objects.get(pk=role.pk).updated_at, later)

    def test_role_id_name_and_scope_type_do_not_change(self):
        """Editing keeps the identity of the role, so its assignments stay valid."""
        role = self.create_role("Designer")

        update_custom_role(role.role_id, description="x", permissions=[EDIT_LIBRARY_CONTENT])

        stored = AuthzRoleDefinition.objects.get(pk=role.pk)
        self.assertEqual((stored.role_id, stored.display_name, stored.scopes), ("custom_designer", "Designer", ["lib"]))

    @data([], ["nope.nope"], [VIEW_COURSE], [None])
    def test_invalid_permissions_leave_the_role_unchanged(self, permissions):
        """An empty, unknown, unsupported or wrongly typed permission list keeps the current grants and policy."""
        role = self.create_role(permissions=[VIEW_LIBRARY])
        policy_before = self.enforcer.get_policy()

        with self.assertRaises(InvalidCustomRoleError):
            update_custom_role(role.role_id, permissions=permissions)

        self.assertEqual(self.enforcer.get_policy(), policy_before)
        self.assertEqual(AuthzRolePermission.objects.filter(role=role).count(), 1)

    def test_hidden_permission_cannot_be_added(self):
        """An edit cannot give a custom role a permission reserved for static roles."""
        role = create_custom_role("Designer", "", COURSE_SCOPE_TYPE, [VIEW_COURSE])

        with self.assertRaisesRegex(InvalidCustomRoleError, HIDDEN_CATEGORY_PERMISSION):
            update_custom_role(role.role_id, permissions=[VIEW_COURSE, HIDDEN_CATEGORY_PERMISSION])

        self.assertEqual(
            list(AuthzRolePermission.objects.filter(role=role).values_list("permission__name", flat=True)),
            ["view_course"],
        )

    def test_description_that_is_not_a_string_is_rejected(self):
        """A non-string description raises instead of reaching the database, and the role keeps its description."""
        role = create_custom_role("Designer", "Original", LIBRARY_SCOPE_TYPE, [VIEW_LIBRARY])

        with self.assertRaises(InvalidCustomRoleError):
            update_custom_role(role.role_id, description=42)

        self.assertEqual(AuthzRoleDefinition.objects.get(pk=role.pk).description, "Original")

    def test_request_without_changes_is_rejected(self):
        """An edit that names neither a description nor permissions is an invalid request."""
        role = self.create_role()

        with self.assertRaises(InvalidCustomRoleError):
            update_custom_role(role.role_id)

    def test_static_role_is_read_only(self):
        """A static role cannot be edited through custom role operations."""
        with self.assertRaises(StaticRoleError):
            update_custom_role("library_admin", description="x")

    def test_unknown_role_is_not_found(self):
        """There is nothing to edit for an ID that does not exist."""
        with self.assertRaises(CustomRoleNotFoundError):
            update_custom_role("custom_missing", description="x")

    def test_removed_role_is_not_found(self):
        """A removed role cannot be edited."""
        role = self.create_role()
        remove_custom_role(role.role_id)

        with self.assertRaises(CustomRoleNotFoundError):
            update_custom_role(role.role_id, description="x")


class TestRemoveCustomRole(CustomRoleTestCase):
    """Removing a role keeps its ID reserved and removes everything that grants access."""

    def test_keeps_the_definition_marked_as_removed(self):
        """The row stays, with the removal time, and drops out of the catalog."""
        role = self.create_role()

        remove_custom_role(role.role_id)

        stored = AuthzRoleDefinition.objects.get(pk=role.pk)
        self.assertIsNotNone(stored.removed_at)
        self.assertNotIn(role.role_id, [item["role"] for item in get_role_catalog([LIBRARY_SCOPE_TYPE])])

    def test_removes_grants_and_policy_rows_and_revokes_access(self):
        """Nothing grants access through the role any more."""
        role = self.create_role()
        self.assign(role)
        self.assertTrue(self.is_allowed(VIEW_LIBRARY))

        remove_custom_role(role.role_id, delete_assignments=True)

        self.assertFalse(AuthzRolePermission.objects.filter(role=role).exists())
        self.assertFalse(self.stored_policy_rows(role.role_id).exists())
        self.assertFalse(self.is_allowed(VIEW_LIBRARY))

    def test_deleted_assignments_leave_no_assignment_records(self):
        """The grouping rows and their extended records are deleted with the role."""
        role = self.create_role()
        self.assign(role)
        self.assertTrue(ExtendedCasbinRule.objects.filter(casbin_rule__v1=make_role_key(role.role_id)).exists())

        remove_custom_role(role.role_id, delete_assignments=True)

        self.assertFalse(CasbinRule.objects.filter(ptype="g", v1=make_role_key(role.role_id)).exists())
        self.assertFalse(ExtendedCasbinRule.objects.filter(casbin_rule__v1=make_role_key(role.role_id)).exists())

    def test_id_stays_reserved(self):
        """A removed role frees its name, but creating a role with it again gives a new ID."""
        removed = self.create_role()
        remove_custom_role(removed.role_id)

        recreated = self.create_role()

        self.assertEqual(recreated.role_id, "custom_designer_2")

    def test_role_with_assignments_requires_explicit_deletion(self):
        """Without the explicit request, a role that is still assigned is left as it was."""
        role = self.create_role()
        self.assign(role)

        with self.assertRaises(CustomRoleHasAssignmentsError) as raised:
            remove_custom_role(role.role_id)

        self.assertEqual(raised.exception.assignment_count, 1)
        self.assertIsNone(AuthzRoleDefinition.objects.get(pk=role.pk).removed_at)
        self.assertTrue(self.is_allowed(VIEW_LIBRARY))

    def test_deleted_assignments_are_recorded_like_other_removals(self):
        """Each deleted assignment sends the same event as an ordinary unassignment."""
        role = self.create_role()
        self.assign(role)

        with patch("openedx_authz.api.roles.ROLE_ASSIGNMENT_DELETED") as signal:
            with self.captureOnCommitCallbacks(execute=True):
                remove_custom_role(role.role_id, delete_assignments=True)

        (call,) = signal.send_event.call_args_list
        sent = call.kwargs["role_assignment"]
        self.assertEqual((sent.subject, sent.role, sent.scope), (ALICE, make_role_key(role.role_id), LIBRARY))

    def test_role_without_assignments_needs_no_confirmation(self):
        """The explicit request is only needed when there is something to delete."""
        role = self.create_role()

        remove_custom_role(role.role_id)

        self.assertIsNotNone(AuthzRoleDefinition.objects.get(pk=role.pk).removed_at)

    def test_static_role_is_read_only(self):
        """A static role cannot be removed through custom role operations."""
        with self.assertRaises(StaticRoleError):
            remove_custom_role("library_admin")

    def test_removed_role_is_not_found(self):
        """Removing the same role twice reports that it is gone."""
        role = self.create_role()
        remove_custom_role(role.role_id)

        with self.assertRaises(CustomRoleNotFoundError):
            remove_custom_role(role.role_id)

    def test_failure_during_removal_rolls_everything_back(self):
        """A failure after the assignment and one grant are deleted restores every row and sends no event."""
        role = self.create_role(permissions=[VIEW_LIBRARY, EDIT_LIBRARY_CONTENT])
        self.assign(role)
        rows_before = sorted(CasbinRule.objects.values_list("ptype", "v0", "v1", "v2", "v3"))
        real_remove = PolicyStore.remove_policy_row
        removed = []

        def fail_on_second_row(store: PolicyStore, row: PolicyRow) -> bool:
            """Remove the first ``p`` row and fail on the next one."""
            if removed:
                raise RuntimeError("simulated failure")
            removed.append(row)
            return real_remove(store, row)

        version_before = PolicyCacheControl.get().version
        with (
            patch.object(PolicyStore, "remove_policy_row", autospec=True, side_effect=fail_on_second_row),
            patch("openedx_authz.api.roles.ROLE_ASSIGNMENT_DELETED") as signal,
            self.captureOnCommitCallbacks(execute=True),
        ):
            with self.assertRaises(RuntimeError):
                remove_custom_role(role.role_id, delete_assignments=True)

        self.assertEqual(len(removed), 1)
        self.assertEqual(sorted(CasbinRule.objects.values_list("ptype", "v0", "v1", "v2", "v3")), rows_before)
        self.assertTrue(ExtendedCasbinRule.objects.filter(casbin_rule__v1=make_role_key(role.role_id)).exists())
        self.assertEqual(AuthzRolePermission.objects.filter(role=role).count(), 2)
        self.assertIsNone(AuthzRoleDefinition.objects.get(pk=role.pk).removed_at)
        signal.send_event.assert_not_called()
        self.assertNotEqual(PolicyCacheControl.get().version, version_before)
        self.assertTrue(self.is_allowed(VIEW_LIBRARY))
        self.assertTrue(self.is_allowed(EDIT_LIBRARY_CONTENT))


class TestAssignCustomRole(CustomRoleTestCase):
    """Only active custom roles can be assigned, and assigning one is serialized with its removal."""

    def test_active_custom_role_can_be_assigned(self):
        """Assigning an active custom role grants its permissions."""
        role = self.create_role()

        self.assertTrue(self.assign(role))
        self.assertTrue(self.is_allowed(VIEW_LIBRARY))

    def test_removed_role_cannot_be_assigned(self):
        """A removed custom role is rejected and no assignment row is written."""
        role = self.create_role()
        remove_custom_role(role.role_id)

        with self.assertRaises(CustomRoleNotFoundError):
            self.assign(role)

        self.assertFalse(CasbinRule.objects.filter(ptype="g", v1=make_role_key(role.role_id)).exists())

    def test_unknown_custom_role_cannot_be_assigned(self):
        """A role ID with the custom prefix and no definition is rejected."""
        with self.assertRaises(CustomRoleNotFoundError):
            assign_role_to_subject_in_scope(
                SubjectData(namespaced_key=ALICE),
                RoleData(external_key="custom_missing"),
                ScopeData(namespaced_key=LIBRARY),
            )

        self.assertFalse(CasbinRule.objects.filter(ptype="g", v1=make_role_key("custom_missing")).exists())

    def test_custom_role_assignment_takes_the_policy_write_lock(self):
        """Assigning a custom role holds the same lock as removing it."""
        role = self.create_role()

        with patch("openedx_authz.engine.policy.PolicyCacheControl.lock", wraps=PolicyCacheControl.lock) as lock:
            self.assign(role)

        lock.assert_called_once_with()

    def test_static_role_assignment_does_not_take_the_lock(self):
        """Static role assignments are not serialized with custom role changes."""
        with patch("openedx_authz.engine.policy.PolicyCacheControl.lock", wraps=PolicyCacheControl.lock) as lock:
            assign_role_to_subject_in_scope(
                SubjectData(namespaced_key=ALICE),
                RoleData(external_key="library_admin"),
                ScopeData(namespaced_key=LIBRARY),
            )

        lock.assert_not_called()

    def test_removal_that_holds_the_lock_first_wins(self):
        """An assignment that waits for a removal to commit sees the role as removed."""
        role = self.create_role()
        real_lock = PolicyCacheControl.lock
        removals = []

        def remove_before_granting_the_lock() -> PolicyCacheControl:
            """Remove the role, as a concurrent removal would, before the assignment gets the lock."""
            if not removals:
                removals.append(role.role_id)
                remove_custom_role(role.role_id)
            return real_lock()

        with patch("openedx_authz.engine.policy.PolicyCacheControl.lock", side_effect=remove_before_granting_the_lock):
            with self.assertRaises(CustomRoleNotFoundError):
                self.assign(role)

        self.assertEqual(removals, [role.role_id])
        self.assertFalse(CasbinRule.objects.filter(ptype="g", v1=make_role_key(role.role_id)).exists())


class TestCustomRolesAndSchemaDeployments(CustomRoleTestCase):
    """The schema loader leaves custom roles alone (ADR 0035 §5)."""

    def test_deployment_keeps_the_role_its_grants_and_access(self):
        """Applying the schema again neither prunes nor reports the custom role."""
        role = self.create_role(permissions=[VIEW_LIBRARY, EDIT_LIBRARY_CONTENT])
        self.assign(role)

        result = SchemaPipeline().apply()
        self.enforcer.load_policy()

        self.assertEqual(result.removed, 0)
        self.assertTrue(AuthzRoleDefinition.objects.user_defined().filter(role_id=role.role_id).exists())
        self.assertEqual(AuthzRolePermission.objects.filter(role=role).count(), 2)
        self.assertEqual(self.stored_policy_rows(role.role_id).count(), 2)
        self.assertTrue(self.is_allowed(VIEW_LIBRARY))
        self.assertTrue(self.is_allowed(EDIT_LIBRARY_CONTENT))
