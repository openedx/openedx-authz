"""Behavioral tests for the ExtendedCasbinRule deletion signal.

Coverage confirms direct deletions, cascades, bulk operations, and resilience when foreign keys
are missing so that the signal stays aligned with the cleanup guarantees in
``openedx_authz.handlers``.
"""

from unittest.mock import patch

from casbin_adapter.models import CasbinRule
from django.test import TestCase

from openedx_authz.models.core import ExtendedCasbinRule, Scope, Subject


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
