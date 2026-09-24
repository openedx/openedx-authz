"""Integration tests for signal handlers in Open edX environment.

These tests verify that signal handlers work correctly when integrated with
the real Open edX platform, particularly testing the user retirement flow.

Run these tests in an edx-platform environment where the USER_RETIRE_LMS_CRITICAL
signal is available.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from openedx.core.djangoapps.user_api.accounts.signals import USER_RETIRE_LMS_CRITICAL  # pylint: disable=import-error

from openedx_authz.api.data import UserData
from openedx_authz.api.users import (
    assign_role_to_user_in_scope,
    get_user_role_assignments,
    get_user_role_assignments_in_scope,
)
from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.models import ExtendedCasbinRule, Subject

User = get_user_model()


class TestUserRetirementSignalIntegration(TestCase):
    """Integration tests for the USER_RETIRE_LMS_CRITICAL signal handler.

    These tests verify that when a user retirement signal is sent in a real Open edX
    environment, all role assignments for the user are properly cleaned up across all scopes.
    """

    def setUp(self):
        """Set up test data with real users and role assignments."""
        # Create real Django users for testing
        self.retiring_user = User.objects.create_user(
            username="retiring_user", email="retiring@example.com", password="testpass123"
        )
        self.other_user = User.objects.create_user(
            username="other_user", email="other@example.com", password="testpass123"
        )

        # Load enforcer policy
        enforcer = AuthzEnforcer.get_enforcer()
        enforcer.load_policy()

    def tearDown(self):
        """Clean up test data."""
        # Clean up users
        User.objects.filter(username__in=["retiring_user", "other_user"]).delete()

        # Clear enforcer policy
        enforcer = AuthzEnforcer.get_enforcer()
        enforcer.clear_policy()

    def test_user_retirement_signal_removes_all_role_assignments(self):
        """Test that sending USER_RETIRE_LMS_CRITICAL removes all roles for a user.

        Expected Result:
            - User has multiple role assignments before signal is sent
            - After signal is sent, user has no role assignments
            - Other users' role assignments are unaffected
        """
        # Assign roles to retiring user in multiple scopes
        assign_role_to_user_in_scope(self.retiring_user.username, "library_admin", "lib:TestOrg:lib1")
        assign_role_to_user_in_scope(self.retiring_user.username, "library_author", "lib:TestOrg:lib2")
        assign_role_to_user_in_scope(self.retiring_user.username, "library_user", "lib:TestOrg:lib3")

        # Assign role to other user
        assign_role_to_user_in_scope(self.other_user.username, "library_admin", "lib:TestOrg:lib4")

        # Verify users have roles before retirement
        retiring_user_roles_before = get_user_role_assignments(self.retiring_user.username)
        other_user_roles_before = get_user_role_assignments(self.other_user.username)

        self.assertEqual(len(retiring_user_roles_before), 3)
        self.assertEqual(len(other_user_roles_before), 1)

        # Send the retirement signal
        USER_RETIRE_LMS_CRITICAL.send(sender=User, user=self.retiring_user)

        # Verify roles are removed for retiring user but not other user
        retiring_user_roles_after = get_user_role_assignments(self.retiring_user.username)
        other_user_roles_after = get_user_role_assignments(self.other_user.username)

        self.assertEqual(len(retiring_user_roles_after), 0)
        self.assertEqual(len(other_user_roles_after), 1)

    def test_user_retirement_signal_with_no_roles(self):
        """Test that retirement signal handles users with no roles gracefully.

        Expected Result:
            - User has no roles before signal
            - Signal completes without error
            - User still has no roles after signal
        """
        # Create user with no role assignments
        user_no_roles = User.objects.create_user(
            username="user_no_roles", email="noroles@example.com", password="testpass123"
        )

        # Verify user has no roles
        user_roles_before = get_user_role_assignments(user_no_roles.username)
        self.assertEqual(len(user_roles_before), 0)

        # Send retirement signal - should not raise error
        USER_RETIRE_LMS_CRITICAL.send(sender=User, user=user_no_roles)

        # Verify still no roles
        user_roles_after = get_user_role_assignments(user_no_roles.username)
        self.assertEqual(len(user_roles_after), 0)

        # Cleanup
        user_no_roles.delete()

    def test_user_retirement_removes_extended_casbin_rules(self):
        """Test that user retirement also cleans up ExtendedCasbinRule records.

        Expected Result:
            - User has ExtendedCasbinRule records linked to their assignments
            - After retirement signal, ExtendedCasbinRule records are removed
            - This ensures complete cleanup including database integrity
        """
        # Assign roles which should create ExtendedCasbinRule records
        assign_role_to_user_in_scope(self.retiring_user.username, "library_admin", "lib:TestOrg:cleanup1")
        assign_role_to_user_in_scope(self.retiring_user.username, "library_author", "lib:TestOrg:cleanup2")

        # Get the subject to check ExtendedCasbinRule records
        user_data = UserData(external_key=self.retiring_user.username)
        subject = Subject.objects.get_or_create_for_external_key(user_data)

        # Verify ExtendedCasbinRule records exist
        extended_rules_before = ExtendedCasbinRule.objects.filter(subject=subject)
        self.assertGreater(extended_rules_before.count(), 0)

        # Send retirement signal
        USER_RETIRE_LMS_CRITICAL.send(sender=User, user=self.retiring_user)

        # Verify ExtendedCasbinRule records are cleaned up
        extended_rules_after = ExtendedCasbinRule.objects.filter(subject=subject)
        self.assertEqual(extended_rules_after.count(), 0)

    def test_user_retirement_with_multiple_scopes_same_role(self):
        """Test retirement for user with same role in multiple scopes.

        Expected Result:
            - User has same role assigned in multiple different scopes
            - After retirement, all assignments across all scopes are removed
            - Role assignments are completely cleared
        """
        scopes = ["lib:Org1:scope1", "lib:Org2:scope2", "lib:Org3:scope3"]

        # Assign same role in multiple scopes
        for scope in scopes:
            assign_role_to_user_in_scope(self.retiring_user.username, "library_admin", scope)

        # Verify assignments in each scope before retirement
        for scope in scopes:
            assignments = get_user_role_assignments_in_scope(self.retiring_user.username, scope)
            self.assertEqual(len(assignments), 1)

        total_assignments_before = get_user_role_assignments(self.retiring_user.username)
        self.assertEqual(len(total_assignments_before), 3)

        # Send retirement signal
        USER_RETIRE_LMS_CRITICAL.send(sender=User, user=self.retiring_user)

        # Verify all assignments removed from all scopes
        for scope in scopes:
            assignments = get_user_role_assignments_in_scope(self.retiring_user.username, scope)
            self.assertEqual(len(assignments), 0)

        total_assignments_after = get_user_role_assignments(self.retiring_user.username)
        self.assertEqual(len(total_assignments_after), 0)

    def test_user_retirement_with_mixed_role_types(self):
        """Test retirement for user with different roles across scopes.

        Expected Result:
            - User has different roles (admin, author, contributor, user) in different scopes
            - After retirement, all roles are removed regardless of type
            - Comprehensive cleanup across all role types
        """
        role_scope_pairs = [
            ("library_admin", "lib:TestOrg:admin_scope"),
            ("library_author", "lib:TestOrg:author_scope"),
            ("library_contributor", "lib:TestOrg:contrib_scope"),
            ("library_user", "lib:TestOrg:user_scope"),
        ]

        # Assign different roles in different scopes
        for role, scope in role_scope_pairs:
            assign_role_to_user_in_scope(self.retiring_user.username, role, scope)

        # Verify all assignments exist
        total_assignments_before = get_user_role_assignments(self.retiring_user.username)
        self.assertEqual(len(total_assignments_before), 4)

        # Extract role types to verify diversity
        roles_before = {r.external_key for assignment in total_assignments_before for r in assignment.roles}
        self.assertEqual(roles_before, {"library_admin", "library_author", "library_contributor", "library_user"})

        # Send retirement signal
        USER_RETIRE_LMS_CRITICAL.send(sender=User, user=self.retiring_user)

        # Verify all roles removed
        total_assignments_after = get_user_role_assignments(self.retiring_user.username)
        self.assertEqual(len(total_assignments_after), 0)

    def test_multiple_user_retirements_do_not_interfere(self):
        """Test that retiring multiple users doesn't affect each other.

        Expected Result:
            - Multiple users each have their own role assignments
            - Retiring one user removes only their assignments
            - Retiring another user removes only their assignments
            - No cross-contamination between user retirements
        """
        # Create additional users
        user1 = User.objects.create_user(username="retire_test_1", email="retire1@example.com", password="testpass123")
        user2 = User.objects.create_user(username="retire_test_2", email="retire2@example.com", password="testpass123")
        user3 = User.objects.create_user(username="retire_test_3", email="retire3@example.com", password="testpass123")

        # Assign roles to each user
        for user in [user1, user2, user3]:
            assign_role_to_user_in_scope(user.username, "library_admin", f"lib:TestOrg:{user.username}_scope")

        # Verify all users have assignments
        for user in [user1, user2, user3]:
            assignments = get_user_role_assignments(user.username)
            self.assertEqual(len(assignments), 1)

        # Retire user1
        USER_RETIRE_LMS_CRITICAL.send(sender=User, user=user1)

        # Verify user1 has no assignments, but user2 and user3 still do
        self.assertEqual(len(get_user_role_assignments(user1.username)), 0)
        self.assertEqual(len(get_user_role_assignments(user2.username)), 1)
        self.assertEqual(len(get_user_role_assignments(user3.username)), 1)

        # Retire user2
        USER_RETIRE_LMS_CRITICAL.send(sender=User, user=user2)

        # Verify user2 has no assignments, but user3 still does
        self.assertEqual(len(get_user_role_assignments(user2.username)), 0)
        self.assertEqual(len(get_user_role_assignments(user3.username)), 1)

        # Cleanup
        for user in [user1, user2, user3]:
            user.delete()
