"""Unit tests for authorization models using stub ContentLibrary.

This test suite verifies the functionality of the authorization models including:
- ExtendedCasbinRule model with metadata and relationships
- Cascade deletion behavior across model hierarchies

These tests use the stub ContentLibrary model from openedx_authz.tests.stubs.models
instead of the real ContentLibrary model, allowing them to run without the full
edx-platform context.

Note: This is a simplified unit test suite. For comprehensive tests of Scope/Subject
polymorphism and registry patterns, see the integration tests in test_integration/test_models.py
which run against the real ContentLibrary model.
"""

from unittest.mock import patch
from uuid import UUID, uuid4

from casbin_adapter.models import CasbinRule
from django.contrib.auth import get_user_model
from django.test import TestCase
from opaque_keys.edx.keys import CourseKey
from opaque_keys.edx.locator import LibraryLocatorV2

from openedx_authz.api.data import ContentLibraryData, CourseOverviewData, UserData
from openedx_authz.models import ExtendedCasbinRule, Scope, Subject
from openedx_authz.models.engine import PolicyCacheControl
from openedx_authz.tests.stubs.models import ContentLibrary, CourseOverview

User = get_user_model()


class TestExtendedCasbinRuleModelWithStub(TestCase):
    """Test cases for the ExtendedCasbinRule model using stub setup."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_username = "test_user"
        self.test_user = User.objects.create_user(username=self.test_username, email="test@example.com")

        self.library_key = LibraryLocatorV2.from_string("lib:TestOrg:TestLib")
        self.content_library = ContentLibrary.objects.get_by_key(self.library_key)

        self.casbin_rule = CasbinRule.objects.create(
            ptype="p",
            v0="user^test_user",
            v1="role^instructor",
            v2="lib^lib:TestOrg:TestLib",
            v3="allow",
        )

        subject_data = UserData(external_key=self.test_username)
        self.subject = Subject.objects.get_or_create_for_external_key(subject_data)

        scope_data = ContentLibraryData(external_key=str(self.library_key))
        self.scope = Scope.objects.get_or_create_for_external_key(scope_data)

    def test_extended_casbin_rule_creation_with_all_fields(self):
        """Test creating ExtendedCasbinRule with all fields populated.

        Expected Result:
        - ExtendedCasbinRule is created successfully.
        - All fields are populated correctly.
        - Timestamps are set automatically.
        """
        casbin_rule_key = (
            f"{self.casbin_rule.ptype},{self.casbin_rule.v0},{self.casbin_rule.v1},"
            f"{self.casbin_rule.v2},{self.casbin_rule.v3}"
        )

        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key,
            casbin_rule=self.casbin_rule,
            description="Test rule for instructor role",
            metadata={"created_by": "test_system", "priority": 1},
            scope=self.scope,
            subject=self.subject,
        )

        self.assertIsNotNone(extended_rule)
        self.assertEqual(extended_rule.casbin_rule_key, casbin_rule_key)
        self.assertEqual(extended_rule.casbin_rule, self.casbin_rule)
        self.assertEqual(extended_rule.description, "Test rule for instructor role")
        self.assertEqual(extended_rule.metadata["created_by"], "test_system")
        self.assertEqual(extended_rule.metadata["priority"], 1)
        self.assertEqual(extended_rule.scope, self.scope)
        self.assertEqual(extended_rule.subject, self.subject)
        self.assertIsNotNone(extended_rule.created_at)
        self.assertIsNotNone(extended_rule.updated_at)
        self.assertEqual(extended_rule.scope.content_library, self.content_library)

    def test_extended_casbin_rule_cascade_deletion_when_scope_deleted(self):
        """Deleting a Scope should cascade to ExtendedCasbinRule and trigger the handler cleanup.

        Expected Result:
        - ExtendedCasbinRule baseline row links the Scope to the CasbinRule.
        - Removing the Scope deletes the ExtendedCasbinRule via database cascade.
        - CasbinRule disappears because the post_delete handler mirrors the cascade.
        """
        casbin_rule_key = (
            f"{self.casbin_rule.ptype},{self.casbin_rule.v0},{self.casbin_rule.v1},"
            f"{self.casbin_rule.v2},{self.casbin_rule.v3}"
        )
        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key,
            casbin_rule=self.casbin_rule,
            scope=self.scope,
        )
        extended_rule_id = extended_rule.id
        casbin_rule_id = self.casbin_rule.id
        scope_id = self.scope.id

        self.scope.delete()

        self.assertFalse(ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists())
        self.assertFalse(CasbinRule.objects.filter(id=casbin_rule_id).exists())
        self.assertFalse(Scope.objects.filter(id=scope_id).exists())

    def test_extended_casbin_rule_cascade_deletion_when_subject_deleted(self):
        """Deleting a Subject should cascade to ExtendedCasbinRule and invoke the handler cleanup.

        Expected Result:
        - ExtendedCasbinRule baseline row links the Subject to the CasbinRule.
        - Removing the Subject deletes the ExtendedCasbinRule via database cascade.
        - CasbinRule disappears because the post_delete handler mirrors the cascade.
        """
        casbin_rule_key = (
            f"{self.casbin_rule.ptype},{self.casbin_rule.v0},{self.casbin_rule.v1},"
            f"{self.casbin_rule.v2},{self.casbin_rule.v3}"
        )
        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key,
            casbin_rule=self.casbin_rule,
            subject=self.subject,
        )
        extended_rule_id = extended_rule.id
        casbin_rule_id = self.casbin_rule.id
        subject_id = self.subject.id

        self.subject.delete()

        self.assertFalse(ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists())
        self.assertFalse(CasbinRule.objects.filter(id=casbin_rule_id).exists())
        self.assertFalse(Subject.objects.filter(id=subject_id).exists())


class TestCourseExtendedCasbinRuleModelWithStub(TestCase):
    """Test cases for the ExtendedCasbinRule model using stub setup and CourseOverview stub."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_username = "test_user"
        self.test_user = User.objects.create_user(username=self.test_username, email="test@example.com")

        self.course_key = CourseKey.from_string("course-v1:TestOrg+TestCourse+2024_T1")
        self.course_overview = CourseOverview.get_from_id(self.course_key)

        self.casbin_rule = CasbinRule.objects.create(
            ptype="p",
            v0="user^test_user",
            v1="role^instructor",
            v2="course-v1^course-v1:TestOrg+TestCourse+2024_T1",
            v3="allow",
        )

        subject_data = UserData(external_key=self.test_username)
        self.subject = Subject.objects.get_or_create_for_external_key(subject_data)

        self.scope_data = CourseOverviewData(external_key=str(self.course_key))
        self.scope = Scope.objects.get_or_create_for_external_key(self.scope_data)

    @patch("openedx_authz.api.data.CourseOverview", CourseOverview)  # Patch to use the stub CourseOverview
    def test_extended_casbin_rule_creation_with_all_fields(self):
        """Test creating ExtendedCasbinRule with all fields populated.

        Expected Result:
        - ExtendedCasbinRule is created successfully.
        - All fields are populated correctly.
        - Timestamps are set automatically.
        """
        casbin_rule_key = (
            f"{self.casbin_rule.ptype},{self.casbin_rule.v0},{self.casbin_rule.v1},"
            f"{self.casbin_rule.v2},{self.casbin_rule.v3}"
        )

        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key,
            casbin_rule=self.casbin_rule,
            description="Test rule for instructor role",
            metadata={"created_by": "test_system", "priority": 1},
            scope=self.scope,
            subject=self.subject,
        )

        self.assertIsNotNone(extended_rule)
        self.assertEqual(extended_rule.casbin_rule_key, casbin_rule_key)
        self.assertEqual(extended_rule.casbin_rule, self.casbin_rule)
        self.assertEqual(extended_rule.description, "Test rule for instructor role")
        self.assertEqual(extended_rule.metadata["created_by"], "test_system")
        self.assertEqual(extended_rule.metadata["priority"], 1)
        self.assertEqual(extended_rule.scope, self.scope)
        self.assertEqual(extended_rule.subject, self.subject)
        self.assertIsNotNone(extended_rule.created_at)
        self.assertIsNotNone(extended_rule.updated_at)
        self.assertEqual(extended_rule.scope.course_overview, self.course_overview)

        # test scope data class details
        self.assertIsInstance(self.scope_data, CourseOverviewData)
        self.assertEqual(self.scope_data.course_id, str(self.course_key))
        self.assertEqual(self.scope_data.external_key, str(self.course_key))
        self.assertEqual(self.scope_data.NAMESPACE, CourseOverviewData.NAMESPACE)
        self.assertTrue(self.scope_data.exists())
        self.assertEqual(self.scope_data.get_object(), self.course_overview)
        self.assertTrue(CourseOverviewData.validate_external_key(self.scope_data.course_id))
        self.assertIsInstance(self.scope_data.course_key, CourseKey)


class TestPolicyCacheControlModel(TestCase):
    """Test cases for the PolicyCacheControl model."""

    def test_get_and_set_version(self):
        """Test getting and setting the cache version.

        Expected Result:
        - Initially, the version is set to a UUID.
        - After setting a new version, it reflects the updated value.
        """
        initial_version = PolicyCacheControl.get_version()
        self.assertIsInstance(initial_version, UUID)

        new_version = uuid4()  # Generate a new UUID
        PolicyCacheControl.set_version(new_version)

        updated_version = PolicyCacheControl.get_version()
        self.assertEqual(updated_version, new_version)

    def test_singleton_behavior(self):
        """Test that only one instance of PolicyCacheControl exists.

        Expected Result:
        - Multiple calls to get() return the same instance.
        - Saving the instance does not create duplicates.
        """
        instance1 = PolicyCacheControl.get()
        instance2 = PolicyCacheControl.get()

        self.assertEqual(instance1.id, instance2.id)

        instance1.save()
        all_instances = PolicyCacheControl.objects.all()
        self.assertEqual(all_instances.count(), 1)
