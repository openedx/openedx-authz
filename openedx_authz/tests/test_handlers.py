"""Tests for ``openedx_authz.handlers``

Coverage confirms direct deletions, cascades, bulk operations, and resilience when foreign keys
are missing so that the signal stays aligned with the cleanup guarantees.

Also covers ``trigger_course_authoring_migration`` using stub waffle model classes (Open edX
waffle models are not imported in the test environment).
"""

from types import SimpleNamespace
from unittest.mock import patch

from casbin_adapter.models import CasbinRule
from ddt import data, ddt, unpack
from django.test import TestCase, override_settings

from openedx_authz.handlers import (
    WAFFLE_OVERRIDE_FORCE_OFF,
    WAFFLE_OVERRIDE_FORCE_ON,
    get_migration_type,
    trigger_course_authoring_migration,
)
from openedx_authz.models.authz_migration import MigrationType, ScopeType
from openedx_authz.models.core import ExtendedCasbinRule, Scope, Subject
from openedx_authz.models.subjects import UserSubject
from openedx_authz.tests.stubs.models import (
    CourseAccessRole,
    WaffleFlagCourseOverrideModel,
    WaffleFlagOrgOverrideModel,
)

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from casbin_adapter.models import CasbinRule
from django.test import TestCase
from openedx_events.authz.data import RoleAssignmentData

from openedx_authz.handlers import create_audit_record_on_role_assignment_change
from openedx_authz.models.core import ExtendedCasbinRule, RoleAssignmentAudit, Scope, Subject

AUTHZ_COURSE_AUTHORING_FLAG_NAME = "authz.enable_course_authoring"
OTHER_WAFFLE_FLAG_NAME = "some.other.flag"


def create_casbin_rule_with_extended(  # pylint: disable=too-many-positional-arguments
    ptype="p",
    v0="user^test_user",
    v1="role^instructor",
    v2="lib^test:library",
    v3="allow",
    scope=None,
    subject=None,
):
    """
    Helper function to create a CasbinRule with an associated ExtendedCasbinRule.

    Args:
        ptype: Policy type (default: "p")
        v0: Policy value 0 (default: "user^test_user")
        v1: Policy value 1 (default: "role^instructor")
        v2: Policy value 2 (default: "lib^test:library")
        v3: Policy value 3 (default: "allow")
        scope: Optional Scope instance to link
        subject: Optional Subject instance to link

    Returns:
        tuple: (casbin_rule, extended_rule)
    """
    casbin_rule = CasbinRule.objects.create(
        ptype=ptype,
        v0=v0,
        v1=v1,
        v2=v2,
        v3=v3,
    )

    casbin_rule_key = f"{casbin_rule.ptype},{casbin_rule.v0},{casbin_rule.v1},{casbin_rule.v2},{casbin_rule.v3}"
    extended_rule = ExtendedCasbinRule.objects.create(
        casbin_rule_key=casbin_rule_key,
        casbin_rule=casbin_rule,
        scope=scope,
        subject=subject,
    )

    return casbin_rule, extended_rule


class TestExtendedCasbinRuleDeletionSignalHandlers(TestCase):
    """Confirm the post_delete handler keeps ExtendedCasbinRule and CasbinRule in sync."""

    def setUp(self):
        """Create a baseline CasbinRule and ExtendedCasbinRule for each test."""
        self.casbin_rule, self.extended_rule = create_casbin_rule_with_extended()

    def test_deleting_extended_casbin_rule_deletes_casbin_rule(self):
        """Deleting an ExtendedCasbinRule directly should trigger the signal that removes the
        linked CasbinRule to avoid orphaned policy records.

        Expected Result:
        - ExtendedCasbinRule record with the captured id no longer exists.
        - Associated CasbinRule row is removed by the signal handler.
        """
        extended_rule_id = self.extended_rule.id
        casbin_rule_id = self.casbin_rule.id

        self.extended_rule.delete()

        self.assertFalse(ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists())
        self.assertFalse(CasbinRule.objects.filter(id=casbin_rule_id).exists())

    def test_deleting_casbin_rule_deletes_extended_casbin_rule(self):
        """Deleting the CasbinRule should cascade through the one-to-one relationship and allow the
        signal handler to exit quietly because the policy row is already gone.

        Expected Result:
        - CasbinRule entry with the captured id no longer exists.
        - ExtendedCasbinRule row cascades away with the same id.
        - Signal completes without raising even though it has nothing left to delete.
        """
        extended_rule_id = self.extended_rule.id
        casbin_rule_id = self.casbin_rule.id

        self.casbin_rule.delete()

        self.assertFalse(ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists())
        self.assertFalse(CasbinRule.objects.filter(id=casbin_rule_id).exists())

    def test_signal_logs_exception_when_casbin_delete_fails(self):
        """A failure deleting the CasbinRule should be logged without blocking later cleanups.

        Expected Result:
        - Logger captures the exception raised by the delete attempt.
        - ExtendedCasbinRule row is removed but the CasbinRule row persists.
        - A subsequent ExtendedCasbinRule deletion still removes both records.
        """
        extended_rule_id = self.extended_rule.id
        casbin_rule_id = self.casbin_rule.id
        extra_casbin_rule, extra_extended_rule = create_casbin_rule_with_extended(
            v0="user^resilient",
            v1="role^assistant",
            v2="lib^resilient",
        )

        with (
            patch("openedx_authz.handlers.logger") as mock_logger,
            patch("openedx_authz.handlers.CasbinRule.objects.filter") as mock_filter,
        ):
            mock_filter.return_value.delete.side_effect = RuntimeError("delete failed")

            self.extended_rule.delete()

            mock_logger.exception.assert_called_once()
            self.assertIn("Error deleting CasbinRule", mock_logger.exception.call_args[0][0])

        self.assertFalse(ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists())
        self.assertTrue(CasbinRule.objects.filter(id=casbin_rule_id).exists())

        extra_extended_rule.delete()

        self.assertFalse(ExtendedCasbinRule.objects.filter(id=extra_extended_rule.id).exists())
        self.assertFalse(CasbinRule.objects.filter(id=extra_casbin_rule.id).exists())

    def test_bulk_delete_extended_casbin_rules_deletes_casbin_rules(self):
        """Bulk deleting ExtendedCasbinRule rows should trigger the signal for each record so all
        related CasbinRule entries disappear.

        Expected Result:
        - All targeted ExtendedCasbinRule ids are absent after the delete call.
        - CasbinRule rows backing those ids are also removed.
        """
        casbin_rule_2, extended_rule_2 = create_casbin_rule_with_extended(
            v0="user^test_user_2",
            v1="role^student",
            v2="lib^test:library_2",
        )

        casbin_rule_ids = [self.casbin_rule.id, casbin_rule_2.id]
        extended_rule_ids = [self.extended_rule.id, extended_rule_2.id]

        ExtendedCasbinRule.objects.filter(id__in=extended_rule_ids).delete()

        self.assertEqual(ExtendedCasbinRule.objects.filter(id__in=extended_rule_ids).count(), 0)
        self.assertEqual(CasbinRule.objects.filter(id__in=casbin_rule_ids).count(), 0)

    def test_cascade_deletion_with_scope_and_subject(self):
        """Deleting a Subject that participates in an ExtendedCasbinRule should cascade through the
        relationship and let the signal clear the CasbinRule while unrelated Scope data stays.

        Expected Result:
        - Subject row is removed.
        - Related ExtendedCasbinRule and CasbinRule instances no longer exist.
        - Scope row referenced in the policy remains in place.
        """
        scope = Scope.objects.create()
        subject = Subject.objects.create()

        casbin_rule, extended_rule = create_casbin_rule_with_extended(
            ptype="g",
            v0="user^test_user",
            v1="role^instructor",
            v2="lib^test:library",
            v3="",
            scope=scope,
            subject=subject,
        )

        casbin_rule_id = casbin_rule.id
        extended_rule_id = extended_rule.id
        scope_id = scope.id
        subject_id = subject.id

        subject.delete()

        self.assertFalse(ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists())
        self.assertFalse(CasbinRule.objects.filter(id=casbin_rule_id).exists())
        self.assertFalse(Subject.objects.filter(id=subject_id).exists())
        self.assertTrue(Scope.objects.filter(id=scope_id).exists())

    def test_cascade_deletion_with_scope_deletion(self):
        """Removing a Scope should cascade through the ExtendedCasbinRule relationship and rely on
        the signal to delete the companion CasbinRule while Subjects remain available.

        Expected Result:
        - Scope row is removed.
        - Related ExtendedCasbinRule and CasbinRule rows no longer exist.
        - Subject row referenced in the policy still exists after the cascade.
        """
        scope = Scope.objects.create()
        subject = Subject.objects.create()

        casbin_rule, extended_rule = create_casbin_rule_with_extended(
            ptype="g",
            v0="user^test_user",
            v1="role^instructor",
            v2="lib^test:library",
            v3="",
            scope=scope,
            subject=subject,
        )

        casbin_rule_id = casbin_rule.id
        extended_rule_id = extended_rule.id
        scope_id = scope.id
        subject_id = subject.id

        scope.delete()

        self.assertFalse(ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists())
        self.assertFalse(CasbinRule.objects.filter(id=casbin_rule_id).exists())
        self.assertFalse(Scope.objects.filter(id=scope_id).exists())
        self.assertTrue(Subject.objects.filter(id=subject_id).exists())


@ddt
@patch("openedx_authz.handlers.run_course_authoring_migration")
@patch.multiple(
    "openedx_authz.handlers",
    AUTHZ_COURSE_AUTHORING_FLAG=SimpleNamespace(name=AUTHZ_COURSE_AUTHORING_FLAG_NAME),
    WaffleFlagCourseOverrideModel=WaffleFlagCourseOverrideModel,
    WaffleFlagOrgOverrideModel=WaffleFlagOrgOverrideModel,
    CourseAccessRole=CourseAccessRole,
)
class TestTriggerCourseAuthoringMigration(TestCase):
    """
    Runs tests for ``trigger_course_authoring_migration`` with stub waffle models.
    """

    COURSE_KEY = "course-v1:test_org+course+run_mm"
    ORG_KEY = "test_org"

    @data(
        (
            WaffleFlagCourseOverrideModel,
            {
                "course_id": COURSE_KEY,
                "waffle_flag": OTHER_WAFFLE_FLAG_NAME,
                "enabled": True,
            },
            COURSE_KEY,
        ),
        (
            WaffleFlagOrgOverrideModel,
            {
                "org": ORG_KEY,
                "waffle_flag": OTHER_WAFFLE_FLAG_NAME,
                "enabled": True,
            },
            ORG_KEY,
        ),
    )
    @unpack
    def test_skips_when_waffle_flag_name_mismatch(self, sender_model, instance_kwargs, scope_key, mock_run):
        """Only the authz course authoring flag triggers migration (course and org overrides)."""
        instance = sender_model(**instance_kwargs)

        trigger_course_authoring_migration(sender_model, instance, scope_key)

        mock_run.assert_not_called()

    @override_settings(ENABLE_AUTOMATIC_AUTHZ_COURSE_AUTHORING_MIGRATION=False)
    @data(
        (
            WaffleFlagCourseOverrideModel,
            {
                "course_id": COURSE_KEY,
                "waffle_flag": AUTHZ_COURSE_AUTHORING_FLAG_NAME,
                "enabled": True,
            },
            COURSE_KEY,
        ),
        (
            WaffleFlagOrgOverrideModel,
            {
                "org": ORG_KEY,
                "waffle_flag": AUTHZ_COURSE_AUTHORING_FLAG_NAME,
                "enabled": True,
            },
            ORG_KEY,
        ),
    )
    @unpack
    @patch("openedx_authz.handlers.logger")
    def test_skips_when_automatic_migration_setting_disabled(
        self, sender_model, instance_kwargs, scope_key, mock_logger, mock_run
    ):  # pylint: disable=too-many-positional-arguments
        """When the setting is off, the handler returns before scheduling work (course and org)."""
        instance = sender_model(**instance_kwargs)

        trigger_course_authoring_migration(sender_model, instance, scope_key)

        mock_run.assert_not_called()
        mock_logger.info.assert_called_once_with(
            "ENABLE_AUTOMATIC_AUTHZ_COURSE_AUTHORING_MIGRATION is set to False, skipping migration"
        )

    @patch("openedx_authz.handlers.logger")
    def test_logs_error_for_unsupported_instance_type(self, mock_logger, mock_run):
        """Instances that are neither course nor org overrides are rejected."""
        unsupported = SimpleNamespace(waffle_flag=AUTHZ_COURSE_AUTHORING_FLAG_NAME, enabled=True, id=9)

        trigger_course_authoring_migration(WaffleFlagCourseOverrideModel, unsupported, "ignored")

        mock_run.assert_not_called()
        mock_logger.error.assert_called_once_with("Unsupported waffle flag instance: %s", unsupported)

    @data(
        (WAFFLE_OVERRIDE_FORCE_ON, MigrationType.FORWARD, True),
        (WAFFLE_OVERRIDE_FORCE_OFF, None, False),
    )
    @unpack
    @patch("openedx_authz.handlers.logger")
    def test_course_scope_migration_depends_on_override_choice(
        self, override_choice, expected_migration_type, expect_migration, mock_logger, mock_run
    ):  # pylint: disable=too-many-positional-arguments
        """Course override runs forward only when forced on, force-off is a no-op for migration."""
        instance = WaffleFlagCourseOverrideModel.objects.create(
            course_id=self.COURSE_KEY,
            waffle_flag=AUTHZ_COURSE_AUTHORING_FLAG_NAME,
            enabled=True,
            override_choice=override_choice,
        )

        trigger_course_authoring_migration(WaffleFlagCourseOverrideModel, instance, self.COURSE_KEY)

        if expect_migration:
            mock_run.assert_called_once_with(
                migration_type=expected_migration_type,
                scope_type=ScopeType.COURSE,
                scope_key=self.COURSE_KEY,
                course_access_role_model=CourseAccessRole,
                user_subject_model=UserSubject,
                course_id_list=[self.COURSE_KEY],
                org_id=None,
                excluded_course_ids=frozenset(),
                delete_after_migration=True,
            )
        else:
            mock_run.assert_not_called()
            mock_logger.info.assert_called_once_with("No effective change in waffle flag behavior, skipping migration")

    @data(
        (WAFFLE_OVERRIDE_FORCE_ON, MigrationType.FORWARD, True),
        (WAFFLE_OVERRIDE_FORCE_OFF, None, False),
    )
    @unpack
    @patch("openedx_authz.handlers.logger")
    def test_org_scope_migration_depends_on_override_choice(
        self, override_choice, expected_migration_type, expect_migration, mock_logger, mock_run
    ):  # pylint: disable=too-many-positional-arguments
        """Org override runs forward only when forced on, force-off is a no-op for migration."""
        instance = WaffleFlagOrgOverrideModel.objects.create(
            org=self.ORG_KEY,
            waffle_flag=AUTHZ_COURSE_AUTHORING_FLAG_NAME,
            enabled=True,
            override_choice=override_choice,
        )

        trigger_course_authoring_migration(WaffleFlagOrgOverrideModel, instance, self.ORG_KEY)

        if expect_migration:
            mock_run.assert_called_once_with(
                migration_type=expected_migration_type,
                scope_type=ScopeType.ORG,
                scope_key=self.ORG_KEY,
                course_access_role_model=CourseAccessRole,
                user_subject_model=UserSubject,
                course_id_list=None,
                org_id=self.ORG_KEY,
                excluded_course_ids=frozenset(),
                delete_after_migration=True,
            )
        else:
            mock_run.assert_not_called()
            mock_logger.info.assert_called_once_with("No effective change in waffle flag behavior, skipping migration")

    def test_org_scope_passes_excluded_course_ids_when_course_overrides_oppose_org(self, mock_run):
        """Org forward migration excludes active course rows whose override opposes force-on."""
        WaffleFlagCourseOverrideModel.objects.create(
            course_id=self.COURSE_KEY,
            waffle_flag=AUTHZ_COURSE_AUTHORING_FLAG_NAME,
            enabled=True,
            override_choice=WAFFLE_OVERRIDE_FORCE_OFF,
        )
        instance = WaffleFlagOrgOverrideModel.objects.create(
            org=self.ORG_KEY,
            waffle_flag=AUTHZ_COURSE_AUTHORING_FLAG_NAME,
            enabled=True,
            override_choice=WAFFLE_OVERRIDE_FORCE_ON,
        )

        trigger_course_authoring_migration(WaffleFlagOrgOverrideModel, instance, self.ORG_KEY)

        mock_run.assert_called_once_with(
            migration_type=MigrationType.FORWARD,
            scope_type=ScopeType.ORG,
            scope_key=self.ORG_KEY,
            course_access_role_model=CourseAccessRole,
            user_subject_model=UserSubject,
            course_id_list=None,
            org_id=self.ORG_KEY,
            excluded_course_ids=frozenset({str(self.COURSE_KEY)}),
            delete_after_migration=True,
        )

    @data(
        (
            WaffleFlagCourseOverrideModel,
            {
                "course_id": COURSE_KEY,
                "waffle_flag": AUTHZ_COURSE_AUTHORING_FLAG_NAME,
                "enabled": True,
                "override_choice": WAFFLE_OVERRIDE_FORCE_ON,
            },
            COURSE_KEY,
        ),
        (
            WaffleFlagOrgOverrideModel,
            {
                "org": ORG_KEY,
                "waffle_flag": AUTHZ_COURSE_AUTHORING_FLAG_NAME,
                "enabled": True,
                "override_choice": WAFFLE_OVERRIDE_FORCE_ON,
            },
            ORG_KEY,
        ),
    )
    @unpack
    @patch("openedx_authz.handlers.logger")
    def test_skips_when_previous_enabled_record_has_same_override_choice(
        self, sender_model, row_kwargs, scope_key, mock_logger, mock_run
    ):  # pylint: disable=too-many-positional-arguments
        """Repeated history rows with the same active override choice do not trigger migration."""
        sender_model.objects.create(**row_kwargs)
        instance = sender_model.objects.create(**row_kwargs)

        trigger_course_authoring_migration(sender_model, instance, scope_key)

        mock_run.assert_not_called()
        mock_logger.info.assert_called_once_with("No effective change in waffle flag behavior, skipping migration")

    @data(
        (
            WaffleFlagCourseOverrideModel,
            {
                "course_id": COURSE_KEY,
                "waffle_flag": AUTHZ_COURSE_AUTHORING_FLAG_NAME,
                "enabled": False,
                "override_choice": WAFFLE_OVERRIDE_FORCE_ON,
            },
            {
                "course_id": COURSE_KEY,
                "waffle_flag": AUTHZ_COURSE_AUTHORING_FLAG_NAME,
                "enabled": True,
                "override_choice": WAFFLE_OVERRIDE_FORCE_ON,
            },
            COURSE_KEY,
        ),
        (
            WaffleFlagOrgOverrideModel,
            {
                "org": ORG_KEY,
                "waffle_flag": AUTHZ_COURSE_AUTHORING_FLAG_NAME,
                "enabled": False,
                "override_choice": WAFFLE_OVERRIDE_FORCE_ON,
            },
            {
                "org": ORG_KEY,
                "waffle_flag": AUTHZ_COURSE_AUTHORING_FLAG_NAME,
                "enabled": True,
                "override_choice": WAFFLE_OVERRIDE_FORCE_ON,
            },
            ORG_KEY,
        ),
    )
    @unpack
    def test_runs_when_previous_record_disabled_even_if_same_override_choice(
        self, sender_model, prev_kwargs, instance_kwargs, scope_key, mock_run
    ):  # pylint: disable=too-many-positional-arguments
        """If the prior row was inactive, a new active row still triggers migration (course and org)."""
        sender_model.objects.create(**prev_kwargs)
        instance = sender_model.objects.create(**instance_kwargs)

        trigger_course_authoring_migration(sender_model, instance, scope_key)

        common = {
            "migration_type": MigrationType.FORWARD,
            "scope_key": scope_key,
            "course_access_role_model": CourseAccessRole,
            "user_subject_model": UserSubject,
            "excluded_course_ids": frozenset(),
            "delete_after_migration": True,
        }
        if sender_model is WaffleFlagCourseOverrideModel:
            mock_run.assert_called_once_with(
                **common,
                scope_type=ScopeType.COURSE,
                course_id_list=[scope_key],
                org_id=None,
            )
        else:
            mock_run.assert_called_once_with(
                **common,
                scope_type=ScopeType.ORG,
                course_id_list=None,
                org_id=scope_key,
            )


class TestGetMigrationType(TestCase):
    """Tests for ``get_migration_type`` (effective state includes ``global_flag_enabled``)."""

    def create_mock_record(self, enabled: bool, choice: str):
        """Helper to create a mock record object."""
        return SimpleNamespace(enabled=enabled, override_choice=choice)

    def test_creation_new_record_enabled_global_off(self):
        """No prior row: enabling FORCE_ON migrates forward when the global flag is off."""
        current = self.create_mock_record(True, WAFFLE_OVERRIDE_FORCE_ON)

        result = get_migration_type(current, None, global_flag_enabled=False)

        self.assertEqual(result, MigrationType.FORWARD)

    def test_creation_new_record_enabled_global_on(self):
        """No prior row: FORCE_ON is already the effective state when global is on — no migration."""
        current = self.create_mock_record(True, WAFFLE_OVERRIDE_FORCE_ON)

        result = get_migration_type(current, None, global_flag_enabled=True)

        self.assertIsNone(result)

    def test_creation_new_record_disabled_matches_global(self):
        """Disabled row defers to global, no previous row means same effective state as global."""
        current = self.create_mock_record(False, WAFFLE_OVERRIDE_FORCE_ON)

        self.assertIsNone(get_migration_type(current, None, global_flag_enabled=False))
        self.assertIsNone(get_migration_type(current, None, global_flag_enabled=True))

    def test_no_change_stay_active_force_on(self):
        """Both enabled FORCE_ON — effective stays on."""
        prev = self.create_mock_record(True, WAFFLE_OVERRIDE_FORCE_ON)
        curr = self.create_mock_record(True, WAFFLE_OVERRIDE_FORCE_ON)

        self.assertIsNone(get_migration_type(curr, prev, global_flag_enabled=False))
        self.assertIsNone(get_migration_type(curr, prev, global_flag_enabled=True))

    def test_no_change_stay_active_force_off(self):
        """Both enabled FORCE_OFF — effective stays off."""
        prev = self.create_mock_record(True, WAFFLE_OVERRIDE_FORCE_OFF)
        curr = self.create_mock_record(True, WAFFLE_OVERRIDE_FORCE_OFF)

        self.assertIsNone(get_migration_type(curr, prev, global_flag_enabled=False))
        self.assertIsNone(get_migration_type(curr, prev, global_flag_enabled=True))

    def test_no_change_stay_inactive(self):
        """Both rows disabled — both follow global, so no effective change."""
        prev = self.create_mock_record(False, WAFFLE_OVERRIDE_FORCE_ON)
        curr = self.create_mock_record(False, WAFFLE_OVERRIDE_FORCE_ON)

        self.assertIsNone(get_migration_type(curr, prev, global_flag_enabled=False))
        self.assertIsNone(get_migration_type(curr, prev, global_flag_enabled=True))

    def test_transition_disabled_to_enabled_force_on_global_off(self):
        """Row becomes active FORCE_ON while global is off — effective off → on."""
        prev = self.create_mock_record(False, WAFFLE_OVERRIDE_FORCE_ON)
        curr = self.create_mock_record(True, WAFFLE_OVERRIDE_FORCE_ON)

        result = get_migration_type(curr, prev, global_flag_enabled=False)

        self.assertEqual(result, MigrationType.FORWARD)

    def test_transition_disabled_to_enabled_force_on_global_on(self):
        """Previously inactive row followed global (on), turning FORCE_ON on stays on — no op."""
        prev = self.create_mock_record(False, WAFFLE_OVERRIDE_FORCE_ON)
        curr = self.create_mock_record(True, WAFFLE_OVERRIDE_FORCE_ON)

        result = get_migration_type(curr, prev, global_flag_enabled=True)

        self.assertIsNone(result)

    def test_transition_enabled_force_on_to_disabled_global_off(self):
        """FORCE_ON row disabled, global off — effective on → off (rollback)."""
        prev = self.create_mock_record(True, WAFFLE_OVERRIDE_FORCE_ON)
        curr = self.create_mock_record(False, WAFFLE_OVERRIDE_FORCE_ON)

        result = get_migration_type(curr, prev, global_flag_enabled=False)

        self.assertEqual(result, MigrationType.ROLLBACK)

    def test_transition_enabled_force_on_to_disabled_global_on(self):
        """FORCE_ON row disabled but global still on — effective stays on, no migration."""
        prev = self.create_mock_record(True, WAFFLE_OVERRIDE_FORCE_ON)
        curr = self.create_mock_record(False, WAFFLE_OVERRIDE_FORCE_ON)

        result = get_migration_type(curr, prev, global_flag_enabled=True)

        self.assertIsNone(result)

    def test_change_choice_force_on_to_force_off(self):
        """Enabled FORCE_ON → FORCE_OFF — effective on → off."""
        prev = self.create_mock_record(True, WAFFLE_OVERRIDE_FORCE_ON)
        curr = self.create_mock_record(True, WAFFLE_OVERRIDE_FORCE_OFF)

        self.assertEqual(
            get_migration_type(curr, prev, global_flag_enabled=False),
            MigrationType.ROLLBACK,
        )
        self.assertEqual(
            get_migration_type(curr, prev, global_flag_enabled=True),
            MigrationType.ROLLBACK,
        )

    def test_change_choice_force_off_to_force_on(self):
        """Enabled FORCE_OFF → FORCE_ON — effective off → on."""
        prev = self.create_mock_record(True, WAFFLE_OVERRIDE_FORCE_OFF)
        curr = self.create_mock_record(True, WAFFLE_OVERRIDE_FORCE_ON)

        self.assertEqual(
            get_migration_type(curr, prev, global_flag_enabled=False),
            MigrationType.FORWARD,
        )
        self.assertEqual(
            get_migration_type(curr, prev, global_flag_enabled=True),
            MigrationType.FORWARD,
        )

    def test_remove_force_off_override_when_global_on(self):
        """Deleting FORCE_OFF behavior by disabling row restores global on — forward migration."""
        prev = self.create_mock_record(True, WAFFLE_OVERRIDE_FORCE_OFF)
        curr = self.create_mock_record(False, WAFFLE_OVERRIDE_FORCE_OFF)

        result = get_migration_type(curr, prev, global_flag_enabled=True)

        self.assertEqual(result, MigrationType.FORWARD)

    def test_remove_force_off_override_when_global_off(self):
        """Disabling FORCE_OFF row while global off — still off, no migration."""
        prev = self.create_mock_record(True, WAFFLE_OVERRIDE_FORCE_OFF)
        curr = self.create_mock_record(False, WAFFLE_OVERRIDE_FORCE_OFF)

        result = get_migration_type(curr, prev, global_flag_enabled=False)

        self.assertIsNone(result)

    def test_add_force_off_override_when_global_on(self):
        """New active FORCE_OFF while global on — effective on → off."""
        prev = self.create_mock_record(False, WAFFLE_OVERRIDE_FORCE_OFF)
        curr = self.create_mock_record(True, WAFFLE_OVERRIDE_FORCE_OFF)

        result = get_migration_type(curr, prev, global_flag_enabled=True)

        self.assertEqual(result, MigrationType.ROLLBACK)

    def test_unknown_override_choice_follows_global(self):
        """Non on/off choice falls back to global — toggling only matters vs that baseline."""
        prev = self.create_mock_record(True, "unset")
        curr = self.create_mock_record(True, "unset")

        self.assertIsNone(get_migration_type(curr, prev, global_flag_enabled=False))
        self.assertIsNone(get_migration_type(curr, prev, global_flag_enabled=True))


class TestCreateAuditRecordHandler(TestCase):
    """Confirm the audit record handler creates RoleAssignmentAudit entries correctly."""

    TIMESTAMP = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)

    def _call_handler(self, role_assignment, timestamp=None):
        """Invoke the handler directly with a mock metadata object."""
        metadata = MagicMock()
        metadata.time = timestamp or self.TIMESTAMP
        create_audit_record_on_role_assignment_change(
            sender=None,
            role_assignment=role_assignment,
            metadata=metadata,
        )

    def test_creates_audit_record_for_created_operation(self):
        """Handler creates a RoleAssignmentAudit row with all fields set correctly.

        Expected result:
        - One RoleAssignmentAudit record exists with operation, subject, role, scope,
          actor_id (None), and the event timestamp.
        """
        role_assignment = RoleAssignmentData(
            operation=RoleAssignmentAudit.OPERATIONS.created,
            subject="user^john_doe",
            role="role^library_admin",
            scope="lib^org1:lib1",
        )

        self._call_handler(role_assignment)

        audit = RoleAssignmentAudit.objects.get()
        self.assertEqual(audit.operation, RoleAssignmentAudit.OPERATIONS.created)
        self.assertEqual(audit.subject, "user^john_doe")
        self.assertEqual(audit.role, "role^library_admin")
        self.assertEqual(audit.scope, "lib^org1:lib1")
        self.assertIsNone(audit.actor_id)
        self.assertEqual(audit.timestamp, self.TIMESTAMP)

    def test_creates_audit_record_for_deleted_operation(self):
        """Handler creates a RoleAssignmentAudit row with operation 'deleted'.

        Expected result:
        - One RoleAssignmentAudit record exists with operation 'deleted'.
        """
        role_assignment = RoleAssignmentData(
            operation=RoleAssignmentAudit.OPERATIONS.deleted,
            subject="user^john_doe",
            role="role^library_admin",
            scope="lib^org1:lib1",
        )

        self._call_handler(role_assignment)

        audit = RoleAssignmentAudit.objects.get()
        self.assertEqual(audit.operation, RoleAssignmentAudit.OPERATIONS.deleted)

    def test_logs_exception_and_does_not_raise_when_creation_fails(self):
        """Handler logs the error without re-raising when RoleAssignmentAudit.create fails.

        Expected result:
        - logger.exception is called once with a message containing 'Error creating audit record'.
        - No RoleAssignmentAudit record is created.
        """
        role_assignment = RoleAssignmentData(
            operation=RoleAssignmentAudit.OPERATIONS.created,
            subject="user^john_doe",
            role="role^library_admin",
            scope="lib^org1:lib1",
        )

        with (
            patch("openedx_authz.handlers.RoleAssignmentAudit.objects.create") as mock_create,
            patch("openedx_authz.handlers.logger") as mock_logger,
        ):
            mock_create.side_effect = Exception("DB error")
            self._call_handler(role_assignment)

        mock_logger.exception.assert_called_once()
        self.assertIn("Error creating audit record", mock_logger.exception.call_args[0][0])
        self.assertEqual(RoleAssignmentAudit.objects.count(), 0)
