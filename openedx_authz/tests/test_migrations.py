"""Unit Tests for openedx_authz migrations."""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase

from openedx_authz.api.users import batch_unassign_role_from_users, get_user_role_assignments_in_scope
from openedx_authz.constants.roles import LIBRARY_ADMIN, LIBRARY_USER
from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.engine.utils import migrate_legacy_permissions
from openedx_authz.tests.stubs.models import ContentLibrary, ContentLibraryPermission, Organization

User = get_user_model()

# Specify a unique prefix to avoid collisions with existing data
OBJECT_PREFIX = "tmlp_"

org_name = f"{OBJECT_PREFIX}org"
lib_name = f"{OBJECT_PREFIX}library"
group_name = f"{OBJECT_PREFIX}test_group"
user_names = [f"{OBJECT_PREFIX}user{i}" for i in range(3)]
group_user_names = [f"{OBJECT_PREFIX}guser{i}" for i in range(3)]
error_user_name = f"{OBJECT_PREFIX}error_user"
error_group_name = f"{OBJECT_PREFIX}error_group"
empty_group_name = f"{OBJECT_PREFIX}empty_group"


class TestLegacyPermissionsMigration(TestCase):
    """Test cases for migrating legacy permissions."""

    def setUp(self):
        """
        Set up test data:

        What this does:
        1. Creates an Org and a ContentLibrary
        2. Create Users and Groups
        3. Assign legacy permissions using ContentLibraryPermission
        4. Create invalid permissions for user and group
        """
        # Create ContentLibrary

        org = Organization.objects.create(name=org_name, short_name=org_name)
        library = ContentLibrary.objects.create(org=org, slug=lib_name)

        # Create Users and Groups
        users = [
            User.objects.create_user(username=user_name, email=f"{user_name}@example.com") for user_name in user_names
        ]

        group_users = [
            User.objects.create_user(username=user_name, email=f"{user_name}@example.com")
            for user_name in group_user_names
        ]
        group = Group.objects.create(name=group_name)
        group.user_set.set(group_users)

        error_user = User.objects.create_user(username=error_user_name, email=f"{error_user_name}@example.com")
        error_group = Group.objects.create(name=error_group_name)
        error_group.user_set.set([error_user])

        empty_group = Group.objects.create(name=empty_group_name)

        # Assign legacy permissions for users and group
        for user in users:
            ContentLibraryPermission.objects.create(
                user=user,
                library=library,
                access_level=ContentLibraryPermission.ADMIN_LEVEL,
            )

        ContentLibraryPermission.objects.create(
            group=group,
            library=library,
            access_level=ContentLibraryPermission.READ_LEVEL,
        )

        # Create invalid permissions for testing error logging
        ContentLibraryPermission.objects.create(
            user=error_user,
            library=library,
            access_level="invalid",
        )
        ContentLibraryPermission.objects.create(
            group=error_group,
            library=library,
            access_level="invalid",
        )

        # Edge case: empty group with no users
        ContentLibraryPermission.objects.create(
            group=empty_group,
            library=library,
            access_level=ContentLibraryPermission.READ_LEVEL,
        )

    def tearDown(self):
        """
        Clean up test data created for the migration test.
        """
        super().tearDown()

        AuthzEnforcer.get_enforcer().load_policy()
        batch_unassign_role_from_users(
            users=user_names,
            role_external_key=LIBRARY_ADMIN.external_key,
            scope_external_key=f"lib:{org_name}:{lib_name}",
        )
        batch_unassign_role_from_users(
            users=group_user_names,
            role_external_key=LIBRARY_USER.external_key,
            scope_external_key=f"lib:{org_name}:{lib_name}",
        )

        ContentLibrary.objects.filter(slug=lib_name).delete()
        Organization.objects.filter(name=org_name).delete()
        Group.objects.filter(name=group_name).delete()
        Group.objects.filter(name=error_group_name).delete()
        Group.objects.filter(name=empty_group_name).delete()
        for user_name in user_names + group_user_names + [error_user_name]:
            User.objects.filter(username=user_name).delete()

    def test_migration(self):
        """Test the migration of legacy permissions.
        1. Rus the migration to migrate legacy permissions.
        2. Check that each user has the expected role in the new model.
        3. Check that the group users have the expected role in the new model.
        4. Check that invalid permissions were identified correctly as errors.
        """

        permissions_with_errors = migrate_legacy_permissions(ContentLibraryPermission)

        AuthzEnforcer.get_enforcer().load_policy()
        for user_name in user_names:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user_name, scope_external_key=f"lib:{org_name}:{lib_name}"
            )
            self.assertEqual(len(assignments), 1)
            self.assertEqual(assignments[0].roles[0], LIBRARY_ADMIN)
        for group_user_name in group_user_names:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=group_user_name, scope_external_key=f"lib:{org_name}:{lib_name}"
            )
            self.assertEqual(len(assignments), 1)
            self.assertEqual(assignments[0].roles[0], LIBRARY_USER)

        self.assertEqual(len(permissions_with_errors), 2)
