"""Shared setup and utilities for REST API view tests."""

from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from openedx_authz.api.users import assign_role_to_user_in_scope
from openedx_authz.constants import roles
from openedx_authz.tests.api.test_roles import BaseRolesTestCase

User = get_user_model()


class ViewTestMixin(BaseRolesTestCase):
    """Mixin providing common test utilities for view tests."""

    @classmethod
    def _assign_roles_to_users(cls, assignments: list[dict] | None = None):
        """Helper method to assign roles to multiple users.

        This method can be used to assign a role to a single user or multiple users
        in a specific scope. It can also handle batch assignments.

        Args:
            assignments (list of dict): List of assignment dictionaries, each containing:
                - subject_name (str): External key of the user (e.g., 'john_doe').
                - role_name (str): External key of the role to assign (e.g., 'library_admin').
                - scope_name (str): External key of the scope in which to assign the role (e.g., 'lib:Org1:math_101').
        """
        for assignment in assignments or []:
            assign_role_to_user_in_scope(
                user_external_key=assignment["subject_name"],
                role_external_key=assignment["role_name"],
                scope_external_key=assignment["scope_name"],
            )

    @classmethod
    def setUpClass(cls):
        """Set up test class with custom role assignments."""
        super().setUpClass()
        assignments = [
            # Assign roles to admin users
            {
                "subject_name": "admin_1",
                "role_name": roles.LIBRARY_ADMIN.external_key,
                "scope_name": "lib:Org1:LIB1",
            },
            {
                "subject_name": "admin_2",
                "role_name": roles.LIBRARY_USER.external_key,
                "scope_name": "lib:Org2:LIB2",
            },
            {
                "subject_name": "admin_3",
                "role_name": roles.LIBRARY_ADMIN.external_key,
                "scope_name": "lib:Org3:LIB3",
            },
            # Assign roles to regular users
            {
                "subject_name": "regular_1",
                "role_name": roles.LIBRARY_USER.external_key,
                "scope_name": "lib:Org1:LIB1",
            },
            {
                "subject_name": "regular_2",
                "role_name": roles.LIBRARY_USER.external_key,
                "scope_name": "lib:Org1:LIB1",
            },
            {
                "subject_name": "regular_3",
                "role_name": roles.LIBRARY_USER.external_key,
                "scope_name": "lib:Org2:LIB2",
            },
            {
                "subject_name": "regular_4",
                "role_name": roles.LIBRARY_USER.external_key,
                "scope_name": "lib:Org2:LIB2",
            },
            {
                "subject_name": "regular_5",
                "role_name": roles.LIBRARY_ADMIN.external_key,
                "scope_name": "lib:Org3:LIB3",
            },
            {
                "subject_name": "regular_6",
                "role_name": roles.LIBRARY_AUTHOR.external_key,
                "scope_name": "lib:Org3:LIB3",
            },
            {
                "subject_name": "regular_7",
                "role_name": "library_contributor",
                "scope_name": "lib:Org3:LIB3",
            },
            {
                "subject_name": "regular_8",
                "role_name": roles.LIBRARY_USER.external_key,
                "scope_name": "lib:Org3:LIB3",
            },
        ]
        cls._assign_roles_to_users(assignments=assignments)

    @classmethod
    def create_regular_users(cls, quantity: int):
        """Create regular users."""
        for i in range(1, quantity + 1):
            User.objects.get_or_create(username=f"regular_{i}", defaults={"email": f"regular_{i}@example.com"})

    @classmethod
    def create_admin_users(cls, quantity: int):
        """Create admin users."""
        for i in range(1, quantity + 1):
            user, created = User.objects.get_or_create(
                username=f"admin_{i}", defaults={"email": f"admin_{i}@example.com"}
            )
            if created:
                user.is_superuser = True
                user.is_staff = True
                user.save()

    @classmethod
    def create_course_users(cls):
        """Create course users (plain, non-staff)."""
        users = ["course_admin", "course_editor", "course_auditor", "course_admin_org", "course_admin_platform"]
        for username in users:
            User.objects.get_or_create(username=username, defaults={"email": f"{username}@example.com"})

    @classmethod
    def create_library_users(cls):
        """Create library users (plain, non-staff)."""
        users = ["library_admin", "library_admin_org", "library_admin_platform"]
        for username in users:
            User.objects.get_or_create(username=username, defaults={"email": f"{username}@example.com"})

    @classmethod
    def setUpTestData(cls):
        """Set up test fixtures once for the entire test class."""
        super().setUpTestData()
        cls.create_admin_users(quantity=3)
        cls.create_regular_users(quantity=10)
        cls.create_course_users()
        cls.create_library_users()

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.client = APIClient()
        self.admin_user = User.objects.get(username="admin_1")
        self.regular_user = User.objects.get(username="regular_1")
        self.client.force_authenticate(user=self.admin_user)
