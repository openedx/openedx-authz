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

from openedx_authz.handlers import trigger_course_authoring_migration
from openedx_authz.models.authz_migration import MigrationType, ScopeType
from openedx_authz.models.core import ExtendedCasbinRule, Scope, Subject
from openedx_authz.models.subjects import UserSubject
from openedx_authz.tests.stubs.models import (
    CourseAccessRole,
    WaffleFlagCourseOverrideModel,
    WaffleFlagOrgOverrideModel,
)

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
    Cover ``trigger_course_authoring_migration`` when Open edX waffle imports are absent.

    The class-level ``patch.multiple`` injects stub models and a stand-in flag into
    ``openedx_authz.handlers`` so ``isinstance`` checks and flag name resolution match production.
    Course and org overrides use the stub ORM (creates and queries) where the handler touches the
    database. A class-level ``patch`` replaces ``run_course_authoring_migration`` so no full
    migration runs; tests that also patch ``logger`` receive that mock before ``mock_run``.
    """

    @override_settings(ENABLE_AUTOMATIC_AUTHZ_COURSE_AUTHORING_MIGRATION=False)
    def test_skips_when_automatic_migration_setting_disabled(self, mock_run):
        """When the setting is off, the handler returns before scheduling work."""
        instance = WaffleFlagCourseOverrideModel(
            course_id="course-v1:org+course+run",
            waffle_flag=AUTHZ_COURSE_AUTHORING_FLAG_NAME,
            enabled=True,
        )

        trigger_course_authoring_migration(
            sender=WaffleFlagCourseOverrideModel,
            instance=instance,
            scope_key=str(instance.course_id),
        )

        mock_run.assert_not_called()

    @data(
        (
            WaffleFlagCourseOverrideModel,
            {
                "course_id": "course-v1:org+course+run_mm",
                "waffle_flag": OTHER_WAFFLE_FLAG_NAME,
                "enabled": True,
            },
            "course-v1:org+course+run_mm",
        ),
        (
            WaffleFlagOrgOverrideModel,
            {
                "org": "test_org_waffle_mm",
                "waffle_flag": OTHER_WAFFLE_FLAG_NAME,
                "enabled": True,
            },
            "test_org_waffle_mm",
        ),
    )
    @unpack
    def test_skips_when_waffle_flag_name_mismatch(self, sender_model, instance_kwargs, scope_key, mock_run):
        """Only the authz course authoring flag triggers migration (course and org overrides)."""
        instance = sender_model(**instance_kwargs)

        trigger_course_authoring_migration(sender_model, instance, scope_key)

        mock_run.assert_not_called()

    @patch("openedx_authz.handlers.logger")
    def test_logs_error_for_unsupported_instance_type(self, mock_logger, mock_run):
        """Instances that are neither course nor org overrides are rejected."""
        unsupported = SimpleNamespace(waffle_flag=AUTHZ_COURSE_AUTHORING_FLAG_NAME, enabled=True, id=9)

        trigger_course_authoring_migration(WaffleFlagCourseOverrideModel, unsupported, "ignored")

        mock_run.assert_not_called()
        mock_logger.error.assert_called_once()
        self.assertIn("Unsupported waffle flag instance", mock_logger.error.call_args[0][0])

    @data(
        (True, MigrationType.FORWARD),
        (False, MigrationType.ROLLBACK),
    )
    @unpack
    def test_course_scope_migration_depends_on_enabled(self, enabled, expected_migration_type, mock_run):
        """Course override runs forward migration when enabled and rollback when disabled."""
        course_key = f"course-v1:test_org+handlers_course+{'on' if enabled else 'off'}"
        instance = WaffleFlagCourseOverrideModel.objects.create(
            course_id=course_key,
            waffle_flag=AUTHZ_COURSE_AUTHORING_FLAG_NAME,
            enabled=enabled,
        )

        trigger_course_authoring_migration(WaffleFlagCourseOverrideModel, instance, course_key)

        mock_run.assert_called_once_with(
            migration_type=expected_migration_type,
            scope_type=ScopeType.COURSE,
            scope_key=course_key,
            course_access_role_model=CourseAccessRole,
            user_subject_model=UserSubject,
            course_id_list=[course_key],
            org_id=None,
        )

    @data(
        (True, MigrationType.FORWARD),
        (False, MigrationType.ROLLBACK),
    )
    @unpack
    def test_org_scope_migration_depends_on_enabled(self, enabled, expected_migration_type, mock_run):
        """Org override runs forward migration when enabled and rollback when disabled."""
        org_name = f"test_org_handlers_{enabled}"
        instance = WaffleFlagOrgOverrideModel.objects.create(
            org=org_name,
            waffle_flag=AUTHZ_COURSE_AUTHORING_FLAG_NAME,
            enabled=enabled,
        )

        trigger_course_authoring_migration(WaffleFlagOrgOverrideModel, instance, org_name)

        mock_run.assert_called_once_with(
            migration_type=expected_migration_type,
            scope_type=ScopeType.ORG,
            scope_key=org_name,
            course_access_role_model=CourseAccessRole,
            user_subject_model=UserSubject,
            course_id_list=None,
            org_id=org_name,
        )

    def test_skips_when_previous_record_has_same_enabled_state(self, mock_run):
        """Repeated saves with the same enabled value do not trigger migration."""
        course_id = "course-v1:test_org+tcam_noop+2024"
        WaffleFlagCourseOverrideModel.objects.create(
            course_id=course_id,
            waffle_flag=AUTHZ_COURSE_AUTHORING_FLAG_NAME,
            enabled=True,
        )
        instance = WaffleFlagCourseOverrideModel.objects.create(
            course_id=course_id,
            waffle_flag=AUTHZ_COURSE_AUTHORING_FLAG_NAME,
            enabled=True,
        )

        trigger_course_authoring_migration(WaffleFlagCourseOverrideModel, instance, course_id)

        mock_run.assert_not_called()
