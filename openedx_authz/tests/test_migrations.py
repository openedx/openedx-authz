"""Unit Tests for openedx_authz migrations."""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.test import TestCase

from openedx_authz.api.users import batch_unassign_role_from_users, get_user_role_assignments_in_scope
from openedx_authz.constants.roles import (
    COURSE_ADMIN,
    COURSE_DATA_RESEARCHER,
    COURSE_LIMITED_STAFF,
    COURSE_STAFF,
    LEGACY_COURSE_ROLE_EQUIVALENCES,
    LIBRARY_ADMIN,
    LIBRARY_USER,
)
from openedx_authz.engine.enforcer import AuthzEnforcer
from openedx_authz.engine.utils import (
    migrate_authz_to_legacy_course_roles,
    migrate_legacy_course_roles_to_authz,
    migrate_legacy_permissions,
)
from openedx_authz.models.subjects import UserSubject
from openedx_authz.tests.stubs.models import (
    ContentLibrary,
    ContentLibraryPermission,
    CourseAccessRole,
    CourseOverview,
    Organization,
)

User = get_user_model()

# Specify a unique prefix to avoid collisions with existing data
OBJECT_PREFIX = "tmlp_"

org_name = f"{OBJECT_PREFIX}org_full_name"
org_short_name = f"{OBJECT_PREFIX}org"
lib_name = f"{OBJECT_PREFIX}library"
group_name = f"{OBJECT_PREFIX}test_group"
user_names = [f"{OBJECT_PREFIX}user{i}" for i in range(3)]
group_user_names = [f"{OBJECT_PREFIX}guser{i}" for i in range(3)]
error_user_name = f"{OBJECT_PREFIX}error_user"
error_group_name = f"{OBJECT_PREFIX}error_group"
empty_group_name = f"{OBJECT_PREFIX}empty_group"


class TestLegacyContentLibraryPermissionsMigration(TestCase):
    """Test cases for migrating legacy content library permissions."""

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

        org = Organization.objects.create(name=org_name, short_name=org_short_name)
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
            scope_external_key=f"lib:{org_short_name}:{lib_name}",
        )
        batch_unassign_role_from_users(
            users=group_user_names,
            role_external_key=LIBRARY_USER.external_key,
            scope_external_key=f"lib:{org_short_name}:{lib_name}",
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
                user_external_key=user_name, scope_external_key=f"lib:{org_short_name}:{lib_name}"
            )
            self.assertEqual(len(assignments), 1)
            self.assertEqual(assignments[0].roles[0], LIBRARY_ADMIN)
        for group_user_name in group_user_names:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=group_user_name, scope_external_key=f"lib:{org_short_name}:{lib_name}"
            )
            self.assertEqual(len(assignments), 1)
            self.assertEqual(assignments[0].roles[0], LIBRARY_USER)

        self.assertEqual(len(permissions_with_errors), 2)


class TestLegacyCourseAuthoringPermissionsMigration(TestCase):
    """Test cases for migrating legacy course authoring permissions."""

    def setUp(self):
        """
        Set up test data:

        What this does:
        1. Defines an Org and a CourseKey for the test course
        2. Create Users for each legacy role and an additional user for testing invalid permissions
        3. Assign legacy permissions using CourseAccessRole for each user and role combination
        4. Create invalid permissions for user to test error logging
         - Notes:
            - CourseAccessRole does not have a group concept, so we are only assigning
                permissions to individual users in this test.
            - The only roles we are migrating are instructor, staff, limited_staff and data_researcher,
                any other role in CourseAccessRole will be considered invalid for the purpose of this test.
        """

        # Defining course identifiers
        self.org = org_short_name
        self.course_id = f"course-v1:{self.org}+{OBJECT_PREFIX}course+2024"
        default_course_fields = {
            "org": self.org,
            "course_id": self.course_id,
        }
        self.course_overview = CourseOverview.objects.create(
            id=self.course_id, org=self.org, display_name=f"{OBJECT_PREFIX} Course"
        )

        # Create lists to hold legacy role objects for cleanup and verification purposes
        self.admin_legacy_roles = []
        self.staff_legacy_roles = []
        self.limited_staff_legacy_roles = []
        self.data_researcher_legacy_roles = []

        # Create users for each legacy role and an additional user for testing invalid permissions
        self.admin_users = [
            User.objects.create_user(username=f"admin_{user_name}", email=f"admin_{user_name}@example.com")
            for user_name in user_names
        ]

        self.staff_users = [
            User.objects.create_user(username=f"staff_{user_name}", email=f"staff_{user_name}@example.com")
            for user_name in user_names
        ]

        self.limited_staff = [
            User.objects.create_user(
                username=f"limited_staff_{user_name}", email=f"limited_staff_{user_name}@example.com"
            )
            for user_name in user_names
        ]

        self.data_researcher = [
            User.objects.create_user(
                username=f"data_researcher_{user_name}", email=f"data_researcher_{user_name}@example.com"
            )
            for user_name in user_names
        ]

        self.error_user = User.objects.create_user(username=error_user_name, email=f"{error_user_name}@example.com")

        # Assign legacy permissions for users based on their role
        for user in self.admin_users:
            leg_role = CourseAccessRole.objects.create(
                **default_course_fields,
                user=user,
                role="instructor",
            )
            self.admin_legacy_roles.append(leg_role)

        for user in self.staff_users:
            leg_role = CourseAccessRole.objects.create(
                **default_course_fields,
                user=user,
                role="staff",
            )
            self.staff_legacy_roles.append(leg_role)

        for user in self.limited_staff:
            leg_role = CourseAccessRole.objects.create(
                **default_course_fields,
                user=user,
                role="limited_staff",
            )
            self.limited_staff_legacy_roles.append(leg_role)

        for user in self.data_researcher:
            leg_role = CourseAccessRole.objects.create(
                **default_course_fields,
                user=user,
                role="data_researcher",
            )
            self.data_researcher_legacy_roles.append(leg_role)

        # Create invalid permission for testing error logging
        CourseAccessRole.objects.create(
            **default_course_fields,
            user=self.error_user,
            role="invalid-legacy-role",
        )

    def tearDown(self):
        """
        Clean up test data created for the migration test.
        """
        super().tearDown()
        AuthzEnforcer.get_enforcer().load_policy()

        admin_users_names = [user.username for user in self.admin_users]
        staff_users_names = [user.username for user in self.staff_users]
        limited_staff_users_names = [user.username for user in self.limited_staff]
        data_researcher_users_names = [user.username for user in self.data_researcher]

        batch_unassign_role_from_users(
            users=admin_users_names,
            role_external_key=COURSE_ADMIN.external_key,
            scope_external_key=self.course_id,
        )
        batch_unassign_role_from_users(
            users=staff_users_names,
            role_external_key=COURSE_STAFF.external_key,
            scope_external_key=self.course_id,
        )
        batch_unassign_role_from_users(
            users=limited_staff_users_names,
            role_external_key=COURSE_LIMITED_STAFF.external_key,
            scope_external_key=self.course_id,
        )
        batch_unassign_role_from_users(
            users=data_researcher_users_names,
            role_external_key=COURSE_DATA_RESEARCHER.external_key,
            scope_external_key=self.course_id,
        )

    def test_legacy_course_role_equivalences_mapping(self):
        """Test that the LEGACY_COURSE_ROLE_EQUIVALENCES mapping contains no duplicate values."""
        legacy_roles = LEGACY_COURSE_ROLE_EQUIVALENCES.keys()
        new_roles = LEGACY_COURSE_ROLE_EQUIVALENCES.values()

        # Check that there are no duplicate values in the mapping
        self.assertEqual(
            len(legacy_roles), len(set(new_roles)), "LEGACY_COURSE_ROLE_EQUIVALENCES contains duplicate values"
        )

    @patch("openedx_authz.api.data.CourseOverview", CourseOverview)
    def test_migrate_legacy_course_roles_to_authz_and_rollback_no_deletion(self):
        """Test the migration of legacy permissions from CourseAccessRole to the new Casbin-based model
        and the rollback functionality without deletion.

        1. Run the migration to migrate legacy permissions from CourseAccessRole to the
            new model with delete_after_migration set to False.
            - Notes:
                - The migration function should correctly map legacy roles to
                    the new roles based on the defined mapping in the migration function.
                - Any legacy role that does not have a defined mapping should be logged as an error
                    and not migrated.
                - After migration, all legacy CourseAccessRole entries should not be deleted
                    since we set delete_after_migration to False.
        2. Check that each user has the expected role in the new model.
        3. Check that invalid permissions were identified correctly as errors.
        4. Rollback the migration and check that each user has the expected legacy role and
            that all migrated permissions were rolled back successfully.
        """

        # Capture the old state of permissions for rollback testing
        original_state_access_roles = list(
            CourseAccessRole.objects.all().order_by("id").values("id", "user_id", "org", "course_id", "role")
        )
        self.assertEqual(
            len(user_names), 3
        )  # Sanity check to ensure we have the expected number of users for each role
        self.assertEqual(
            len(original_state_access_roles), 13
        )  # 3 users for each of the 4 roles + 1 invalid role = 13 total entries

        # Migrate from legacy CourseAccessRole to new Casbin-based model
        permissions_with_errors = migrate_legacy_course_roles_to_authz(CourseAccessRole, delete_after_migration=False)
        AuthzEnforcer.get_enforcer().load_policy()
        for user in self.admin_users:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            self.assertEqual(len(assignments), 1)
            self.assertEqual(assignments[0].roles[0], COURSE_ADMIN)
        for user in self.staff_users:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            self.assertEqual(len(assignments), 1)
            self.assertEqual(assignments[0].roles[0], COURSE_STAFF)
        for user in self.limited_staff:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            self.assertEqual(len(assignments), 1)
            self.assertEqual(assignments[0].roles[0], COURSE_LIMITED_STAFF)
        for user in self.data_researcher:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            self.assertEqual(len(assignments), 1)
            self.assertEqual(assignments[0].roles[0], COURSE_DATA_RESEARCHER)
        self.assertEqual(len(permissions_with_errors), 1)
        self.assertEqual(permissions_with_errors[0].user.username, self.error_user.username)
        self.assertEqual(permissions_with_errors[0].role, "invalid-legacy-role")

        after_migrate_state_access_roles = list(
            CourseAccessRole.objects.all().order_by("id").values("id", "user_id", "org", "course_id", "role")
        )

        # 3 users for each of the 4 roles + 1 invalid role = 13 total entries
        self.assertEqual(len(after_migrate_state_access_roles), 13)
        # Must be the same before and after migration since we set delete_after_migration to False
        self.assertEqual(original_state_access_roles, after_migrate_state_access_roles)

        # Now let's rollback

        # Capture the state of permissions before rollback to verify that rollback restores the original state
        original_state_user_subjects = list(
            UserSubject.objects.filter(casbin_rules__scope__coursescope__course_overview__isnull=False)
            .distinct()
            .order_by("id")
            .values("id", "user_id")
        )
        original_state_access_roles = list(
            CourseAccessRole.objects.all().order_by("id").values("id", "user_id", "org", "course_id", "role")
        )

        permissions_with_errors = migrate_authz_to_legacy_course_roles(
            CourseAccessRole, UserSubject, delete_after_migration=False
        )

        # Check that each user has the expected legacy role after rollback and that errors
        # are logged for any permissions that could not be rolled back
        for user in self.admin_users:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            self.assertEqual(len(assignments), 1)
            self.assertEqual(assignments[0].roles[0], COURSE_ADMIN)
        for user in self.staff_users:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            self.assertEqual(len(assignments), 1)
            self.assertEqual(assignments[0].roles[0], COURSE_STAFF)
        for user in self.limited_staff:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            self.assertEqual(len(assignments), 1)
            self.assertEqual(assignments[0].roles[0], COURSE_LIMITED_STAFF)
        for user in self.data_researcher:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            self.assertEqual(len(assignments), 1)
            self.assertEqual(assignments[0].roles[0], COURSE_DATA_RESEARCHER)
        self.assertEqual(len(permissions_with_errors), 0)

        state_after_migration_user_subjects = list(
            UserSubject.objects.filter(casbin_rules__scope__coursescope__course_overview__isnull=False)
            .distinct()
            .order_by("id")
            .values("id", "user_id")
        )
        after_migrate_state_access_roles = list(
            CourseAccessRole.objects.all().order_by("id").values("id", "user_id", "org", "course_id", "role")
        )

        # The number of CourseAccessRole entries should be the same as the original state
        # since we are not deleting any entries in this test.
        self.assertEqual(len(original_state_access_roles), 13)

        # All original entries should still be there since we are not deleting any entries
        # and when creating new entries for the users that were migrated back to legacy roles,
        # we are creating them with get_or_create which will not create duplicates if an entry
        # with the same user, org, course_id and role already exists.
        self.assertEqual(len(after_migrate_state_access_roles), 13)

        # Sanity check to ensure we have the expected number of UserSubjects related to
        # the course permissions before migration (3 users * 4 roles = 12)
        self.assertEqual(len(original_state_user_subjects), 12)

        # After rollback, we should have the same 12 UserSubjects related to the course permissions
        # since we are not deleting any entries in this test,
        self.assertEqual(len(state_after_migration_user_subjects), 12)

    @patch("openedx_authz.api.data.CourseOverview", CourseOverview)
    def test_migrate_legacy_course_roles_to_authz_and_rollback_with_deletion(self):
        """Test the migration of legacy permissions from CourseAccessRole to
        the new Casbin-based model with deletion of legacy permissions after migration.

        1. Run the migration to migrate legacy permissions from CourseAccessRole to the
            new model with delete_after_migration set to True.
            - Notes:
                - The migration function should correctly map legacy roles to
                    the new roles based on the defined mapping in the migration function.
                - Any legacy role that does not have a defined mapping should be logged as an error
                    and not migrated.
                - After migration, all legacy CourseAccessRole entries should be deleted
                    since we set delete_after_migration to True.
        2. Check that each user has the expected role in the new model.
        3. Check that invalid permissions were identified correctly as errors.
        4. Rollback the migration and check that each user has the expected legacy role and
            that all migrated permissions were rolled back successfully.
        """

        # Capture the old state of permissions for rollback testing
        original_state_access_roles = list(
            CourseAccessRole.objects.all().order_by("id").values("id", "user_id", "org", "course_id", "role")
        )
        self.assertEqual(
            len(user_names), 3
        )  # Sanity check to ensure we have the expected number of users for each role
        self.assertEqual(
            len(original_state_access_roles), 13
        )  # 3 users for each of the 4 roles + 1 invalid role = 13 total entries

        # Migrate from legacy CourseAccessRole to new Casbin-based model
        permissions_with_errors = migrate_legacy_course_roles_to_authz(CourseAccessRole, delete_after_migration=True)
        AuthzEnforcer.get_enforcer().load_policy()
        for user in self.admin_users:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            self.assertEqual(len(assignments), 1)
            self.assertEqual(assignments[0].roles[0], COURSE_ADMIN)
        for user in self.staff_users:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            self.assertEqual(len(assignments), 1)
            self.assertEqual(assignments[0].roles[0], COURSE_STAFF)
        for user in self.limited_staff:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            self.assertEqual(len(assignments), 1)
            self.assertEqual(assignments[0].roles[0], COURSE_LIMITED_STAFF)
        for user in self.data_researcher:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            self.assertEqual(len(assignments), 1)
            self.assertEqual(assignments[0].roles[0], COURSE_DATA_RESEARCHER)
        self.assertEqual(len(permissions_with_errors), 1)
        self.assertEqual(permissions_with_errors[0].user.username, self.error_user.username)
        self.assertEqual(permissions_with_errors[0].role, "invalid-legacy-role")

        after_migrate_state_access_roles = list(
            CourseAccessRole.objects.all().order_by("id").values("id", "user_id", "org", "course_id", "role")
        )

        self.assertEqual(len(original_state_access_roles), 13)

        # Only the invalid role entry should remain since we set delete_after_migration to True
        self.assertEqual(len(after_migrate_state_access_roles), 1)

        # Must be different before and after migration since we set delete_after_migration
        # to True and we are deleting all
        self.assertNotEqual(original_state_access_roles, after_migrate_state_access_roles)

        # Now let's rollback

        # Capture the state of permissions before rollback to verify that rollback restores the original state
        original_state_user_subjects = list(
            UserSubject.objects.filter(casbin_rules__scope__coursescope__course_overview__isnull=False)
            .distinct()
            .order_by("id")
            .values("id", "user_id")
        )
        original_state_access_roles = list(
            CourseAccessRole.objects.all().order_by("id").values("id", "user_id", "org", "course_id", "role")
        )

        permissions_with_errors = migrate_authz_to_legacy_course_roles(
            CourseAccessRole, UserSubject, delete_after_migration=True
        )

        # Check that each user has the expected legacy role after rollback
        # and that errors are logged for any permissions that could not be rolled back
        for user in self.admin_users:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            self.assertEqual(len(assignments), 0)
        for user in self.staff_users:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            self.assertEqual(len(assignments), 0)
        for user in self.limited_staff:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            self.assertEqual(len(assignments), 0)
        for user in self.data_researcher:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            self.assertEqual(len(assignments), 0)
        self.assertEqual(len(permissions_with_errors), 0)

        state_after_migration_user_subjects = list(
            UserSubject.objects.filter(casbin_rules__scope__coursescope__course_overview__isnull=False)
            .distinct()
            .order_by("id")
            .values("id", "user_id")
        )
        after_migrate_state_access_roles = list(
            CourseAccessRole.objects.all().order_by("id").values("id", "user_id", "org", "course_id", "role")
        )

        # Before the rollback, we should only have the 1 invalid role entry
        # since we set delete_after_migration to True in the migration.
        self.assertEqual(len(original_state_access_roles), 1)

        # All original entries + 3 users * 4 roles = 12
        # plus the original invalid entry = 1 + 12 = 13 total entries
        self.assertEqual(len(after_migrate_state_access_roles), 1 + 12)

        # Sanity check to ensure we have the expected number of UserSubjects related to
        # the course permissions before migration (3 users * 4 roles = 12)
        self.assertEqual(len(original_state_user_subjects), 12)

        # After rollback, we should have 0 UserSubjects related to the course permissions
        self.assertEqual(len(state_after_migration_user_subjects), 0)

    @patch("openedx_authz.api.data.CourseOverview", CourseOverview)
    def test_migrate_legacy_course_roles_to_authz_and_rollback_with_no_new_role_equivalent(self):
        """Test the migration of legacy course roles to the new Casbin-based model
        and the rollback when there is no equivalent new role.
        """

        # Migrate from legacy CourseAccessRole to new Casbin-based model
        permissions_with_errors = migrate_legacy_course_roles_to_authz(CourseAccessRole, delete_after_migration=True)
        AuthzEnforcer.get_enforcer().load_policy()

        # Now let's rollback

        # Capture the state of permissions before rollback to verify that rollback restores the original state
        original_state_user_subjects = list(
            UserSubject.objects.filter(casbin_rules__scope__coursescope__course_overview__isnull=False)
            .distinct()
            .order_by("id")
            .values("id", "user_id")
        )
        original_state_access_roles = list(
            CourseAccessRole.objects.all().order_by("id").values("id", "user_id", "org", "course_id", "role")
        )

        # Mock the COURSE_ROLE_EQUIVALENCES mapping to only include a mapping
        # for COURSE_ADMIN to simulate the scenario where the staff, limited_staff
        # and data_researcher roles do not have a legacy role equivalent and
        # therefore cannot be migrated back to legacy roles during the rollback.
        with patch(
            "openedx_authz.engine.utils.COURSE_ROLE_EQUIVALENCES",
            {COURSE_ADMIN.external_key: "instructor"},
        ):
            permissions_with_errors = migrate_authz_to_legacy_course_roles(
                CourseAccessRole, UserSubject, delete_after_migration=True
            )

        # Check that each user has the expected legacy role after rollback
        # and that errors are logged for any permissions that could not be rolled back
        for user in self.admin_users:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            self.assertEqual(len(assignments), 0)
        for user in self.staff_users:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            # Since we are mocking the COURSE_ROLE_EQUIVALENCES mapping to only include a mapping for COURSE_ADMIN,
            # the staff role will not have a legacy role equivalent and therefore should not be migrated back
            self.assertEqual(len(assignments), 1)
        for user in self.limited_staff:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            # Since we are mocking the COURSE_ROLE_EQUIVALENCES mapping to only include a mapping for COURSE_ADMIN,
            # the limited_staff role will not have a legacy role equivalent and therefore should not be migrated back
            self.assertEqual(len(assignments), 1)
        for user in self.data_researcher:
            assignments = get_user_role_assignments_in_scope(
                user_external_key=user.username, scope_external_key=self.course_id
            )
            # Since we are mocking the COURSE_ROLE_EQUIVALENCES mapping to only include a mapping for COURSE_ADMIN,
            # the data_researcher role will not have a legacy role equivalent and therefore should not be migrated back
            self.assertEqual(len(assignments), 1)

        # 3 staff + 3 limited_staff + 3 data_researcher = 9 entries with no legacy role equivalent
        self.assertEqual(len(permissions_with_errors), 9)

        state_after_migration_user_subjects = list(
            UserSubject.objects.filter(casbin_rules__scope__coursescope__course_overview__isnull=False)
            .distinct()
            .order_by("id")
            .values("id", "user_id")
        )
        after_migrate_state_access_roles = list(
            CourseAccessRole.objects.all().order_by("id").values("id", "user_id", "org", "course_id", "role")
        )

        # Before the rollback, we should only have the 1 invalid role entry
        # since we set delete_after_migration to True in the migration.
        self.assertEqual(len(original_state_access_roles), 1)

        # All original entries (1) + 3 users * 1 roles = 4
        self.assertEqual(len(after_migrate_state_access_roles), 1 + 3)

        # Before the rollback, we should have the 12 UserSubjects related to the course permissions
        # since we had 3 users with 4 roles each in the original state.
        self.assertEqual(len(original_state_user_subjects), 12)

        # After rollback, we should have 9 UserSubjects related to the course permissions
        # since the users with staff, limited_staff and data_researcher roles will not be
        # migrated back to legacy roles due to our mocked COURSE_ROLE_EQUIVALENCES mapping.
        self.assertEqual(len(state_after_migration_user_subjects), 9)

    @patch("openedx_authz.management.commands.authz_migrate_course_authoring.CourseAccessRole", CourseAccessRole)
    @patch("openedx_authz.management.commands.authz_migrate_course_authoring.migrate_legacy_course_roles_to_authz")
    def test_authz_migrate_course_authoring_command(self, mock_migrate):
        """
        Verify that the authz_migrate_course_authoring command
        calls migrate_legacy_course_roles_to_authz with the correct arguments.
        """

        mock_migrate.return_value = []

        # Run without --delete
        call_command("authz_migrate_course_authoring")

        mock_migrate.assert_called_once()
        args, kwargs = mock_migrate.call_args

        self.assertEqual(kwargs["delete_after_migration"], False)

        mock_migrate.reset_mock()

        # Run with --delete
        with patch("builtins.input", return_value="yes"):
            call_command("authz_migrate_course_authoring", "--delete")

        mock_migrate.assert_called_once()
        args, kwargs = mock_migrate.call_args

        self.assertEqual(kwargs["delete_after_migration"], True)

    @patch("openedx_authz.management.commands.authz_rollback_course_authoring.CourseAccessRole", CourseAccessRole)
    @patch("openedx_authz.management.commands.authz_rollback_course_authoring.migrate_authz_to_legacy_course_roles")
    def test_authz_rollback_course_authoring_command(self, mock_rollback):
        """
        Verify that the authz_rollback_course_authoring command
        calls migrate_authz_to_legacy_course_roles correctly.
        """

        mock_rollback.return_value = []

        # Run without --delete
        call_command("authz_rollback_course_authoring")

        mock_rollback.assert_called_once()
        args, kwargs = mock_rollback.call_args

        self.assertEqual(kwargs["delete_after_migration"], False)

        mock_rollback.reset_mock()

        # Run with --delete
        with patch("builtins.input", return_value="yes"):
            call_command("authz_rollback_course_authoring", "--delete")

        self.assertEqual(mock_rollback.call_count, 1)

        call_kwargs = mock_rollback.call_args_list[0][1]

        self.assertEqual(call_kwargs["delete_after_migration"], True)
