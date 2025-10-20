"""Test cases for authorization models.

This test suite verifies the functionality of the authorization models including:
- Scope model with ContentLibrary integration
- Subject model with User integration
- Polymorphic behavior and registry pattern for Scope and Subject models
- ExtendedCasbinRule model with metadata and relationships
- Cascade deletion behavior across model hierarchies

Notes:
 - Tests use the parent models (Scope, Subject) with polymorphic dispatch
     via manager methods to reflect actual production usage.
 - Where enforcer behaviour is required, tests use mock enforcer instances
     (see `TestExtendedCasbinRuleCreateBasedOnPolicy`) to avoid the full
     platform enforcer infrastructure.

Run these tests in an environment where openedx.core.djangoapps.content_libraries.models
is accessible (e.g., edx-platform with content libraries installed).
"""

import uuid
from unittest.mock import Mock
from ddt import ddt

import pytest
from casbin_adapter.models import CasbinRule
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import TestCase, override_settings
from organizations.api import ensure_organization
from organizations.models import Organization

from openedx_authz.api.data import ContentLibraryData, RoleData, UserData
from openedx_authz.engine.filter import Filter
from openedx_authz.models import (
    ContentLibrary,
    ExtendedCasbinRule,
    Scope,
    Subject,
    ContentLibraryScope,
    UserSubject,
)
import openedx.core.djangoapps.content_libraries.api as library_api

User = get_user_model()


def create_test_library(org_short_name, slug=None, title="Test Library"):
    """
    Helper function to create a content library using the proper API.

    This uses library_api.create_library() which:
    - Creates the ContentLibrary database record
    - Creates the associated LearningPackage
    - Fires CONTENT_LIBRARY_CREATED event
    - Returns ContentLibraryMetadata

    Args:
        org_short_name: Organization short name (e.g., "TestOrg")
        slug: Library slug (e.g., "TestLib"). If None, generates a unique slug using uuid4.
        title: Library title (default: "Test Library")

    Returns:
        tuple: (library_metadata, library_key, content_library)
            - library_metadata: ContentLibraryMetadata instance from API
            - library_key: LibraryLocatorV2 instance
            - content_library: ContentLibrary model instance
    """
    # Generate unique slug if not provided
    if slug is None:
        slug = f"testlib-{uuid.uuid4().hex[:8]}"

    # ensure_organization returns a dict, so we need to get the actual model instance
    ensure_organization(org_short_name)
    org = Organization.objects.get(short_name=org_short_name)

    library_metadata = library_api.create_library(
        org=org,
        slug=slug,
        title=title,
        description=f"A library for testing authorization: {slug}",
    )
    library_key = library_metadata.key
    # Note: ContentLibrary model doesn't have library_key as a database field
    # It's a property constructed from org and slug. Use get_by_key() method.
    content_library = ContentLibrary.objects.get_by_key(library_key)
    return library_metadata, library_key, content_library


@ddt
@override_settings(OPENEDX_AUTHZ_CONTENT_LIBRARY_MODEL='content_libraries.ContentLibrary')
class TestScopeModel(TestCase):
    """Test cases for the Scope model.

    These tests create ContentLibrary instances via the content library API and
    exercise the Scope manager helpers using ContentLibraryData objects to test
    the polymorphic behavior.
    """

    def setUp(self):
        """Set up test fixtures."""
        # Create library using the API helper (auto-generates unique slug)
        self.library_metadata, self.library_key, self.content_library = (
            create_test_library(
                org_short_name="TestOrg",
            )
        )

    def test_get_or_create_for_external_key_creates_new(self):
        """Test that get_or_create_for_external_key creates a new Scope when none exists.

        Expected result:
            - Scope is created successfully
            - Scope is linked to the ContentLibrary
            - Only one Scope exists for the ContentLibrary
        """
        scope_data = ContentLibraryData(external_key=str(self.library_key))

        scope = Scope.objects.get_or_create_for_external_key(scope_data)

        self.assertIsNotNone(scope)
        self.assertIsInstance(scope, ContentLibraryScope)
        self.assertEqual(scope.content_library, self.content_library)
        # Can also access via parent -> child relationship
        self.assertEqual(
            Scope.objects.filter(contentlibraryscope__content_library=self.content_library).count(), 1
        )

    def test_get_or_create_for_external_key_gets_existing(self):
        """Test that get_or_create_for_external_key retrieves existing Scope.

        Expected result:
            - First call creates the Scope
            - Second call retrieves the same Scope
            - Only one Scope exists for the ContentLibrary
        """
        scope_data = ContentLibraryData(external_key=str(self.library_key))

        scope1 = Scope.objects.get_or_create_for_external_key(scope_data)
        scope2 = Scope.objects.get_or_create_for_external_key(scope_data)

        self.assertEqual(scope1.id, scope2.id)
        self.assertEqual(
            ContentLibraryScope.objects.filter(content_library=self.content_library).count(), 1
        )

    def test_scope_can_be_created_without_content_library(self):
        """Test that Scope can be created without a content_library.

        Expected result:
            - Scope is created successfully
            - content_library field is None
        """
        scope = Scope.objects.create()

        self.assertIsNotNone(scope)
        self.assertIsNone(getattr(scope, 'content_library', None))

    def test_scope_cascade_deletion_when_content_library_deleted(self):
        """Test that Scope is deleted when its ContentLibrary is deleted.

        Expected result:
            - Scope is created successfully
            - Deleting ContentLibrary also deletes the Scope
        """
        scope_data = ContentLibraryData(external_key=str(self.library_key))
        scope = Scope.objects.get_or_create_for_external_key(scope_data)
        scope_id = scope.id

        self.content_library.delete()

        self.assertFalse(Scope.objects.filter(id=scope_id).exists())


@pytest.mark.integration
@override_settings(OPENEDX_AUTHZ_CONTENT_LIBRARY_MODEL='content_libraries.ContentLibrary')
class TestSubjectModel(TestCase):
    """Test cases for the Subject model.

    These tests create User instances and exercise the Subject manager helpers
    using UserData objects to test the polymorphic behavior.
    """

    def setUp(self):
        """Set up test fixtures."""
        self.test_username = "test_user"
        self.test_user = User.objects.create_user(username=self.test_username)

    def test_get_or_create_for_external_key_creates_new(self):
        """Test that get_or_create_for_external_key creates a new Subject when none exists.

        Expected result:
            - Subject is created successfully
            - Subject is linked to the User
            - Only one Subject exists for the User
        """
        subject_data = UserData(external_key=self.test_username)

        subject = Subject.objects.get_or_create_for_external_key(subject_data)

        self.assertIsNotNone(subject)
        self.assertIsInstance(subject, UserSubject)
        self.assertEqual(subject.user, self.test_user)
        # Can also access via parent -> child relationship
        self.assertEqual(Subject.objects.filter(usersubject__user=self.test_user).count(), 1)

    def test_get_or_create_for_external_key_gets_existing(self):
        """Test that get_or_create_for_external_key retrieves existing Subject.

        Expected result:
            - First call creates the Subject
            - Second call retrieves the same Subject
            - Only one Subject exists for the User
        """
        subject_data = UserData(external_key=self.test_username)

        subject1 = Subject.objects.get_or_create_for_external_key(subject_data)
        subject2 = Subject.objects.get_or_create_for_external_key(subject_data)

        self.assertEqual(subject1.id, subject2.id)
        # Can also access via parent -> child relationship
        self.assertEqual(Subject.objects.filter(usersubject__user=self.test_user).count(), 1)

    def test_subject_can_be_created_without_user(self):
        """Test that Subject can be created without a user.

        Expected result:
            - Subject is created successfully
            - user field is None
        """
        subject = Subject.objects.create()

        self.assertIsNotNone(subject)
        self.assertIsNone(getattr(subject, 'user', None))

    def test_subject_cascade_deletion_when_user_deleted(self):
        """Test that Subject is deleted when its User is deleted.

        Expected result:
            - Subject is created successfully
            - Deleting User also deletes the Subject
        """
        subject_data = UserData(external_key=self.test_username)
        subject = Subject.objects.get_or_create_for_external_key(subject_data)
        subject_id = subject.id

        self.test_user.delete()

        self.assertFalse(Subject.objects.filter(id=subject_id).exists())


@pytest.mark.integration
@override_settings(OPENEDX_AUTHZ_CONTENT_LIBRARY_MODEL='content_libraries.ContentLibrary')
class TestPolymorphicBehavior(TestCase):
    """Test cases for polymorphic behavior of Scope and Subject models.

    These tests verify that:
    - The registry pattern correctly maps namespaces to subclasses
    - Manager methods dispatch to the correct subclass based on namespace
    - Queries return instances of the correct polymorphic type
    - Multiple subclass types can coexist in the database
    """

    def setUp(self):
        """Set up test fixtures."""
        self.test_username = "test_user"
        self.test_user = User.objects.create_user(username=self.test_username)

        # Create library using the API helper (auto-generates unique slug)
        self.library_metadata, self.library_key, self.content_library = (
            create_test_library(
                org_short_name="TestOrg",
            )
        )

    def test_scope_registry_contains_content_library_namespace(self):
        """Test that ContentLibraryScope is registered in Scope._registry.

        Expected result:
            - 'lib' namespace is present in registry
            - Registry maps 'lib' to ContentLibraryScope class
        """
        self.assertIn('lib', Scope._registry)
        self.assertEqual(Scope._registry['lib'], ContentLibraryScope)

    def test_subject_registry_contains_user_namespace(self):
        """Test that UserSubject is registered in Subject._registry.

        Expected result:
            - 'user' namespace is present in registry
            - Registry maps 'user' to UserSubject class
        """
        self.assertIn('user', Subject._registry)
        self.assertEqual(Subject._registry['user'], UserSubject)

    def test_scope_manager_dispatches_to_content_library_scope(self):
        """Test that Scope manager dispatches to ContentLibraryScope for 'lib' namespace.

        Expected result:
            - Scope.objects.get_or_create_for_external_key returns ContentLibraryScope instance
            - Instance has content_library attribute
            - Instance is linked to the correct ContentLibrary
        """
        scope_data = ContentLibraryData(external_key=str(self.library_key))

        scope = Scope.objects.get_or_create_for_external_key(scope_data)

        self.assertIsInstance(scope, ContentLibraryScope)
        self.assertTrue(hasattr(scope, 'content_library'))
        self.assertEqual(scope.content_library, self.content_library)

    def test_subject_manager_dispatches_to_user_subject(self):
        """Test that Subject manager dispatches to UserSubject for 'user' namespace.

        Expected result:
            - Subject.objects.get_or_create_for_external_key returns UserSubject instance
            - Instance has user attribute
            - Instance is linked to the correct User
        """
        subject_data = UserData(external_key=self.test_username)

        subject = Subject.objects.get_or_create_for_external_key(subject_data)

        self.assertIsInstance(subject, UserSubject)
        self.assertTrue(hasattr(subject, 'user'))
        self.assertEqual(subject.user, self.test_user)

    def test_scope_manager_raises_error_for_unregistered_namespace(self):
        """Test that Scope manager raises ValueError for unknown namespace.

        Expected result:
            - ValueError is raised when namespace not in registry
            - Error message indicates the unknown namespace
        """
        from openedx_authz.api.data import ScopeData

        # Create a scope data with a namespace that doesn't exist
        class UnregisteredScopeData(ScopeData):
            NAMESPACE = "unregistered"

        unregistered_data = UnregisteredScopeData(external_key="some_key")

        with self.assertRaises(ValueError) as context:
            Scope.objects.get_or_create_for_external_key(unregistered_data)

        self.assertIn("unregistered", str(context.exception))

    def test_subject_manager_raises_error_for_unregistered_namespace(self):
        """Test that Subject manager raises ValueError for unknown namespace.

        Expected result:
            - ValueError is raised when namespace not in registry
            - Error message indicates the unknown namespace
        """
        from openedx_authz.api.data import SubjectData

        # Create a subject data with a namespace that doesn't exist
        class UnregisteredSubjectData(SubjectData):
            NAMESPACE = "unregistered"

        unregistered_data = UnregisteredSubjectData(external_key="some_key")

        with self.assertRaises(ValueError) as context:
            Subject.objects.get_or_create_for_external_key(unregistered_data)

        self.assertIn("unregistered", str(context.exception))

    def test_multiple_scope_types_can_coexist(self):
        """Test that different Scope subclasses can coexist in the database.

        Expected result:
            - Base Scope table contains both ContentLibraryScope and plain Scope
            - Each can be queried independently
            - Total Scope count includes all types
        """
        # Create a ContentLibraryScope via the manager
        scope_data = ContentLibraryData(external_key=str(self.library_key))
        content_library_scope = Scope.objects.get_or_create_for_external_key(scope_data)

        # Create a plain Scope instance
        plain_scope = Scope.objects.create()

        # Query all Scopes - Django returns base type instances
        all_scopes = Scope.objects.all()
        all_scope_ids = set(all_scopes.values_list('id', flat=True))

        self.assertEqual(all_scopes.count(), 2)
        self.assertIn(content_library_scope.id, all_scope_ids)
        self.assertIn(plain_scope.id, all_scope_ids)

        # Verify we can query the specific subclass
        content_library_scopes = ContentLibraryScope.objects.all()
        self.assertEqual(content_library_scopes.count(), 1)
        self.assertEqual(content_library_scopes.first().id, content_library_scope.id)

    def test_multiple_subject_types_can_coexist(self):
        """Test that different Subject subclasses can coexist in the database.

        Expected result:
            - Base Subject table contains both UserSubject and plain Subject
            - Each can be queried independently
            - Total Subject count includes all types
        """
        # Create a UserSubject via the manager
        subject_data = UserData(external_key=self.test_username)
        user_subject = Subject.objects.get_or_create_for_external_key(subject_data)

        # Create a plain Subject instance
        plain_subject = Subject.objects.create()

        # Query all Subjects - Django returns base type instances
        all_subjects = Subject.objects.all()
        all_subject_ids = set(all_subjects.values_list('id', flat=True))

        self.assertEqual(all_subjects.count(), 2)
        self.assertIn(user_subject.id, all_subject_ids)
        self.assertIn(plain_subject.id, all_subject_ids)

        # Verify we can query the specific subclass
        user_subjects = UserSubject.objects.all()
        self.assertEqual(user_subjects.count(), 1)
        self.assertEqual(user_subjects.first().id, user_subject.id)

    def test_scope_query_returns_polymorphic_instances(self):
        """Test that querying Scope returns the correct polymorphic instance type.

        Expected result:
            - Querying by ID returns ContentLibraryScope instance, not base Scope
            - Instance retains all subclass attributes and methods
        """
        scope_data = ContentLibraryData(external_key=str(self.library_key))
        created_scope = Scope.objects.get_or_create_for_external_key(scope_data)

        # Query by ID from base Scope manager
        queried_scope = Scope.objects.get(id=created_scope.id)

        # Note: Django's default multi-table inheritance returns the base type
        # unless you use select_related or query the subclass directly
        # This test documents the current behavior
        self.assertIsInstance(queried_scope, Scope)

        # To get the polymorphic instance, query the subclass
        polymorphic_scope = ContentLibraryScope.objects.get(id=created_scope.id)
        self.assertIsInstance(polymorphic_scope, ContentLibraryScope)
        self.assertEqual(polymorphic_scope.content_library, self.content_library)

    def test_subject_query_returns_polymorphic_instances(self):
        """Test that querying Subject returns the correct polymorphic instance type.

        Expected result:
            - Querying by ID returns UserSubject instance when queried from subclass
            - Instance retains all subclass attributes and methods
        """
        subject_data = UserData(external_key=self.test_username)
        created_subject = Subject.objects.get_or_create_for_external_key(subject_data)

        # Query by ID from base Subject manager
        queried_subject = Subject.objects.get(id=created_subject.id)

        # Note: Django's default multi-table inheritance returns the base type
        # unless you use select_related or query the subclass directly
        self.assertIsInstance(queried_subject, Subject)

        # To get the polymorphic instance, query the subclass
        polymorphic_subject = UserSubject.objects.get(id=created_subject.id)
        self.assertIsInstance(polymorphic_subject, UserSubject)
        self.assertEqual(polymorphic_subject.user, self.test_user)

    def test_scope_namespace_class_variable_is_set(self):
        """Test that Scope subclasses have NAMESPACE class variable set.

        Expected result:
            - ContentLibraryScope.NAMESPACE is 'lib'
            - Base Scope.NAMESPACE is None
        """
        self.assertEqual(ContentLibraryScope.NAMESPACE, 'lib')
        self.assertIsNone(Scope.NAMESPACE)

    def test_subject_namespace_class_variable_is_set(self):
        """Test that Subject subclasses have NAMESPACE class variable set.

        Expected result:
            - UserSubject.NAMESPACE is 'user'
            - Base Subject.NAMESPACE is None
        """
        self.assertEqual(UserSubject.NAMESPACE, 'user')
        self.assertIsNone(Subject.NAMESPACE)


@pytest.mark.integration
@override_settings(OPENEDX_AUTHZ_CONTENT_LIBRARY_MODEL='content_libraries.ContentLibrary')
class TestExtendedCasbinRuleModel(TestCase):
    """Test cases for the ExtendedCasbinRule model."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_username = "test_user"
        self.test_user = User.objects.create_user(username=self.test_username)

        # Create library using the API helper (auto-generates unique slug)
        self.library_metadata, self.library_key, self.content_library = (
            create_test_library(
                org_short_name="TestOrg",
            )
        )

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

        Expected result:
            - ExtendedCasbinRule is created successfully
            - All fields are populated correctly
            - Timestamps are set automatically
        """
        casbin_rule_key = f"{self.casbin_rule.ptype},{self.casbin_rule.v0},{self.casbin_rule.v1},{self.casbin_rule.v2},{self.casbin_rule.v3}"

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

    def test_extended_casbin_rule_unique_key_constraint(self):
        """Test that casbin_rule_key must be unique.

        Expected result:
            - First ExtendedCasbinRule is created successfully
            - Second ExtendedCasbinRule with same key raises IntegrityError
        """
        casbin_rule_key = f"{self.casbin_rule.ptype},{self.casbin_rule.v0},{self.casbin_rule.v1},{self.casbin_rule.v2},{self.casbin_rule.v3}"

        ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key, casbin_rule=self.casbin_rule
        )

        casbin_rule2 = CasbinRule.objects.create(
            ptype="p",
            v0="user^test_user2",
            v1="role^admin",
            v2="lib^lib:TestOrg:TestLib2",
            v3="allow",
        )

        with self.assertRaises(IntegrityError):
            ExtendedCasbinRule.objects.create(
                casbin_rule_key=casbin_rule_key, casbin_rule=casbin_rule2
            )

    def test_extended_casbin_rule_cascade_deletion_when_casbin_rule_deleted(self):
        """Test that ExtendedCasbinRule is deleted when its CasbinRule is deleted.

        Expected result:
            - ExtendedCasbinRule is created successfully
            - Deleting CasbinRule also deletes the ExtendedCasbinRule
        """
        casbin_rule_key = f"{self.casbin_rule.ptype},{self.casbin_rule.v0},{self.casbin_rule.v1},{self.casbin_rule.v2},{self.casbin_rule.v3}"
        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key, casbin_rule=self.casbin_rule
        )
        extended_rule_id = extended_rule.id

        self.casbin_rule.delete()

        self.assertFalse(
            ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists()
        )

    def test_extended_casbin_rule_cascade_deletion_when_scope_deleted(self):
        """Test that ExtendedCasbinRule is deleted when its Scope is deleted.

        Expected result:
            - ExtendedCasbinRule is created successfully
            - Deleting Scope also deletes the ExtendedCasbinRule
        """
        casbin_rule_key = f"{self.casbin_rule.ptype},{self.casbin_rule.v0},{self.casbin_rule.v1},{self.casbin_rule.v2},{self.casbin_rule.v3}"
        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key,
            casbin_rule=self.casbin_rule,
            scope=self.scope,
        )
        extended_rule_id = extended_rule.id

        self.scope.delete()

        self.assertFalse(
            ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists()
        )

    def test_extended_casbin_rule_cascade_deletion_when_subject_deleted(self):
        """Test that ExtendedCasbinRule is deleted when its Subject is deleted.

        Expected result:
            - ExtendedCasbinRule is created successfully
            - Deleting Subject also deletes the ExtendedCasbinRule
        """
        casbin_rule_key = f"{self.casbin_rule.ptype},{self.casbin_rule.v0},{self.casbin_rule.v1},{self.casbin_rule.v2},{self.casbin_rule.v3}"
        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key,
            casbin_rule=self.casbin_rule,
            subject=self.subject,
        )
        extended_rule_id = extended_rule.id

        self.subject.delete()

        self.assertFalse(
            ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists()
        )

    def test_extended_casbin_rule_metadata_json_field(self):
        """Test that metadata JSONField can store complex data structures.

        Expected result:
            - ExtendedCasbinRule stores complex metadata
            - Metadata is retrieved correctly from database
            - Nested structures are preserved
        """
        casbin_rule_key = f"{self.casbin_rule.ptype},{self.casbin_rule.v0},{self.casbin_rule.v1},{self.casbin_rule.v2},{self.casbin_rule.v3}"
        complex_metadata = {
            "tags": ["test", "instructor", "library"],
            "config": {
                "enabled": True,
                "priority": 10,
                "features": ["read", "write", "delete"],
            },
            "audit": {"created_by": "system", "last_modified_by": "admin"},
        }

        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key,
            casbin_rule=self.casbin_rule,
            metadata=complex_metadata,
        )

        retrieved_rule = ExtendedCasbinRule.objects.get(id=extended_rule.id)

        self.assertEqual(
            retrieved_rule.metadata["tags"], ["test", "instructor", "library"]
        )
        self.assertEqual(retrieved_rule.metadata["config"]["enabled"], True)
        self.assertEqual(retrieved_rule.metadata["config"]["priority"], 10)
        self.assertEqual(retrieved_rule.metadata["audit"]["created_by"], "system")

    def test_extended_casbin_rule_verbose_names(self):
        """Test that model has correct verbose names.

        Expected result:
            - Singular verbose name is correct
            - Plural verbose name is correct
        """
        self.assertEqual(ExtendedCasbinRule._meta.verbose_name, "Extended Casbin Rule")
        self.assertEqual(
            ExtendedCasbinRule._meta.verbose_name_plural, "Extended Casbin Rules"
        )

    def test_extended_casbin_rule_can_be_created_without_optional_fields(self):
        """Test that ExtendedCasbinRule can be created with only required fields.

        Expected result:
            - ExtendedCasbinRule is created with required fields only
            - Optional fields are None/null
        """
        casbin_rule_key = "p,user^test2,role^viewer,lib^lib:Org:Lib2,allow"
        casbin_rule2 = CasbinRule.objects.create(
            ptype="p",
            v0="user^test2",
            v1="role^viewer",
            v2="lib^lib:Org:Lib2",
            v3="allow",
        )

        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key, casbin_rule=casbin_rule2
        )

        self.assertIsNotNone(extended_rule)
        self.assertIsNone(extended_rule.description)
        self.assertIsNone(extended_rule.metadata)
        self.assertIsNone(extended_rule.scope)
        self.assertIsNone(extended_rule.subject)


@pytest.mark.integration
@override_settings(OPENEDX_AUTHZ_CONTENT_LIBRARY_MODEL='content_libraries.ContentLibrary')
class TestExtendedCasbinRuleCreateBasedOnPolicy(TestCase):
    """Test cases for ExtendedCasbinRule.create_based_on_policy method.

    These tests use a mock enforcer to avoid dependencies on the full
    enforcer infrastructure.
    """

    def setUp(self):
        """Set up test fixtures."""
        self.test_username = "test_user"
        self.test_user = User.objects.create_user(username=self.test_username)

        # Create library using the API helper (auto-generates unique slug)
        self.library_metadata, self.library_key, self.content_library = (
            create_test_library(
                org_short_name="TestOrg",
            )
        )

    def test_create_based_on_policy_generates_correct_casbin_rule_key(self):
        """Test that create_based_on_policy generates the correct unique casbin_rule_key.

        Expected result:
            - ExtendedCasbinRule is created successfully
            - casbin_rule_key follows expected format
            - Related Scope and Subject are linked correctly
        """
        subject_data = UserData(external_key=self.test_username)
        role_data = RoleData(external_key="instructor")
        scope_data = ContentLibraryData(external_key=str(self.library_key))

        subject = Subject.objects.get_or_create_for_external_key(subject_data)
        scope = Scope.objects.get_or_create_for_external_key(scope_data)

        casbin_rule = CasbinRule.objects.create(
            ptype="g",
            v0=subject_data.namespaced_key,
            v1=role_data.namespaced_key,
            v2=scope_data.namespaced_key,
            v3="",
        )

        mock_enforcer = Mock()
        mock_enforcer.adapter = Mock()
        mock_enforcer.adapter.query_policy.return_value = Mock(first=Mock(return_value=casbin_rule))

        expected_key = f"g,{subject_data.namespaced_key},{role_data.namespaced_key},{scope_data.namespaced_key},"

        result = ExtendedCasbinRule.create_based_on_policy(
            subject=subject_data,
            role=role_data,
            scope=scope_data,
            enforcer=mock_enforcer,
        )

        self.assertEqual(result.casbin_rule_key, expected_key)
        self.assertEqual(result.casbin_rule, casbin_rule)
        self.assertEqual(result.scope, scope)
        self.assertEqual(result.subject, subject)

    def test_create_based_on_policy_is_idempotent(self):
        """Test that calling create_based_on_policy multiple times with same params returns same rule.

        Expected result:
            - First call creates the ExtendedCasbinRule
            - Second call returns the same ExtendedCasbinRule
            - Only one ExtendedCasbinRule exists
        """
        subject_data = UserData(external_key=self.test_username)
        role_data = RoleData(external_key="instructor")
        scope_data = ContentLibraryData(external_key=str(self.library_key))

        subject = Subject.objects.get_or_create_for_external_key(subject_data)
        scope = Scope.objects.get_or_create_for_external_key(scope_data)

        casbin_rule = CasbinRule.objects.create(
            ptype="g",
            v0=subject_data.namespaced_key,
            v1=role_data.namespaced_key,
            v2=scope_data.namespaced_key,
            v3="",
        )

        mock_enforcer = Mock()
        mock_enforcer.adapter = Mock()
        mock_enforcer.adapter.query_policy.return_value = Mock(first=Mock(return_value=casbin_rule))

        result1 = ExtendedCasbinRule.create_based_on_policy(
            subject=subject_data,
            role=role_data,
            scope=scope_data,
            enforcer=mock_enforcer,
        )

        result2 = ExtendedCasbinRule.create_based_on_policy(
            subject=subject_data,
            role=role_data,
            scope=scope_data,
            enforcer=mock_enforcer,
        )

        self.assertEqual(result1.id, result2.id)
        self.assertEqual(ExtendedCasbinRule.objects.count(), 1)

    def test_create_based_on_policy_calls_enforcer_query_with_filter(self):
        """Test that create_based_on_policy calls enforcer.query_policy with correct Filter.

        Expected result:
            - enforcer.query_policy is called exactly once
            - Filter object is used as argument
        """
        subject_data = UserData(external_key=self.test_username)
        role_data = RoleData(external_key="instructor")
        scope_data = ContentLibraryData(external_key=str(self.library_key))

        Subject.objects.get_or_create_for_external_key(subject_data)
        Scope.objects.get_or_create_for_external_key(scope_data)

        casbin_rule = CasbinRule.objects.create(
            ptype="g",
            v0=subject_data.namespaced_key,
            v1=role_data.namespaced_key,
            v2=scope_data.namespaced_key,
            v3="",
        )

        mock_enforcer = Mock()
        mock_enforcer.adapter = Mock()
        mock_enforcer.adapter.query_policy.return_value = Mock(first=Mock(return_value=casbin_rule))

        ExtendedCasbinRule.create_based_on_policy(
            subject=subject_data,
            role=role_data,
            scope=scope_data,
            enforcer=mock_enforcer,
        )

        mock_enforcer.adapter.query_policy.assert_called_once()
        call_args = mock_enforcer.adapter.query_policy.call_args[0][0]
        self.assertIsInstance(call_args, Filter)


@pytest.mark.integration
@override_settings(OPENEDX_AUTHZ_CONTENT_LIBRARY_MODEL='content_libraries.ContentLibrary')
class TestModelRelationships(TestCase):
    """Test cases for model relationships and related_name attributes."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_username = "test_user"
        self.test_user = User.objects.create_user(username=self.test_username)
        subject_data = UserData(external_key=self.test_username)
        self.subject = Subject.objects.get_or_create_for_external_key(subject_data)

        # Create library using the API helper (auto-generates unique slug)
        self.library_metadata, self.library_key, self.content_library = (
            create_test_library(
                org_short_name="TestOrg",
            )
        )

        self.casbin_rule = CasbinRule.objects.create(
            ptype="p",
            v0="user^test_user",
            v1="role^instructor",
            v2="lib^lib:TestOrg:TestLib",
            v3="allow",
        )

    def test_user_can_access_subjects_via_related_name(self):
        """Test that User can access related Subject objects via authz_subjects.

        Expected result:
            - User has exactly one related Subject
            - Related Subject matches the created Subject
        """
        self.assertEqual(self.test_user.authz_subjects.count(), 1)
        self.assertEqual(self.test_user.authz_subjects.first(), self.subject)

    def test_subject_can_access_casbin_rules_via_related_name(self):
        """Test that Subject can access related ExtendedCasbinRule objects via casbin_rules.

        Expected result:
            - Subject has exactly one related ExtendedCasbinRule
            - Related ExtendedCasbinRule matches the created rule
        """
        casbin_rule_key = f"{self.casbin_rule.ptype},{self.casbin_rule.v0},{self.casbin_rule.v1},{self.casbin_rule.v2},{self.casbin_rule.v3}"
        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key,
            casbin_rule=self.casbin_rule,
            subject=self.subject,
        )

        self.assertEqual(self.subject.casbin_rules.count(), 1)
        self.assertEqual(self.subject.casbin_rules.first(), extended_rule)

    def test_scope_can_access_casbin_rules_via_related_name(self):
        """Test that Scope can access related ExtendedCasbinRule objects via casbin_rules.

        Expected result:
            - Scope has exactly one related ExtendedCasbinRule
            - Related ExtendedCasbinRule matches the created rule
        """
        scope_data = ContentLibraryData(external_key=str(self.library_key))
        scope = Scope.objects.get_or_create_for_external_key(scope_data)

        casbin_rule_key = f"{self.casbin_rule.ptype},{self.casbin_rule.v0},{self.casbin_rule.v1},{self.casbin_rule.v2},{self.casbin_rule.v3}"
        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key, casbin_rule=self.casbin_rule, scope=scope
        )

        self.assertEqual(scope.casbin_rules.count(), 1)
        self.assertEqual(scope.casbin_rules.first(), extended_rule)

    def test_casbin_rule_can_access_extended_rule_via_related_name(self):
        """Test that CasbinRule can access related ExtendedCasbinRule via extended_rule.

        Expected result:
            - CasbinRule has exactly one related ExtendedCasbinRule
            - Related ExtendedCasbinRule matches the created rule
        """
        casbin_rule_key = f"{self.casbin_rule.ptype},{self.casbin_rule.v0},{self.casbin_rule.v1},{self.casbin_rule.v2},{self.casbin_rule.v3}"
        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key, casbin_rule=self.casbin_rule
        )

        self.assertEqual(self.casbin_rule.extended_rule.count(), 1)
        self.assertEqual(self.casbin_rule.extended_rule.first(), extended_rule)

    def test_content_library_can_access_scopes_via_related_name(self):
        """Test that ContentLibrary can access related Scope objects via authz_scopes.

        Expected result:
            - ContentLibrary has exactly one related Scope
            - Related Scope matches the created Scope
        """
        scope_data = ContentLibraryData(external_key=str(self.library_key))
        scope = Scope.objects.get_or_create_for_external_key(scope_data)

        self.assertEqual(self.content_library.authz_scopes.count(), 1)
        self.assertEqual(self.content_library.authz_scopes.first(), scope)


@pytest.mark.integration
@override_settings(OPENEDX_AUTHZ_CONTENT_LIBRARY_MODEL='content_libraries.ContentLibrary')
class TestModelCascadeDeletionChain(TestCase):
    """Test cases for cascade deletion chains across multiple models."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_username = "test_user"
        self.test_user = User.objects.create_user(username=self.test_username)

        # Create library using the API helper (auto-generates unique slug)
        self.library_metadata, self.library_key, self.content_library = (
            create_test_library(
                org_short_name="TestOrg",
            )
        )

    def test_content_library_deletion_cascades_to_extended_casbin_rules(self):
        """Test that deleting ContentLibrary cascades through Scope to ExtendedCasbinRule.

        Expected result:
            - Deleting ContentLibrary deletes the Scope
            - Deleting Scope cascades to delete ExtendedCasbinRule
        """
        scope_data = ContentLibraryData(external_key=str(self.library_key))
        scope = Scope.objects.get_or_create_for_external_key(scope_data)

        casbin_rule = CasbinRule.objects.create(
            ptype="p",
            v0="user^test_user",
            v1="role^instructor",
            v2=scope_data.namespaced_key,
            v3="allow",
        )

        casbin_rule_key = f"{casbin_rule.ptype},{casbin_rule.v0},{casbin_rule.v1},{casbin_rule.v2},{casbin_rule.v3}"
        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key, casbin_rule=casbin_rule, scope=scope
        )
        extended_rule_id = extended_rule.id

        self.content_library.delete()

        self.assertFalse(Scope.objects.filter(id=scope.id).exists())
        self.assertFalse(
            ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists()
        )

    def test_user_deletion_cascades_to_extended_casbin_rules(self):
        """Test that deleting User cascades through Subject to ExtendedCasbinRule.

        Expected result:
            - Deleting User deletes the Subject
            - Deleting Subject cascades to delete ExtendedCasbinRule
        """
        subject_data = UserData(external_key=self.test_username)
        subject = Subject.objects.get_or_create_for_external_key(subject_data)

        casbin_rule = CasbinRule.objects.create(
            ptype="p",
            v0=subject_data.namespaced_key,
            v1="role^instructor",
            v2="lib^lib:TestOrg:TestLib",
            v3="allow",
        )

        casbin_rule_key = f"{casbin_rule.ptype},{casbin_rule.v0},{casbin_rule.v1},{casbin_rule.v2},{casbin_rule.v3}"
        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key, casbin_rule=casbin_rule, subject=subject
        )
        extended_rule_id = extended_rule.id

        self.test_user.delete()

        self.assertFalse(Subject.objects.filter(id=subject.id).exists())
        self.assertFalse(
            ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists()
        )

    def test_complete_cascade_deletion_chain(self):
        """Test complete cascade deletion with all models linked together.

        Expected result:
            - Deleting CasbinRule deletes ExtendedCasbinRule
            - Subject and Scope remain after ExtendedCasbinRule deletion
            - User and ContentLibrary remain after ExtendedCasbinRule deletion
        """
        subject_data = UserData(external_key=self.test_username)
        subject = Subject.objects.get_or_create_for_external_key(subject_data)

        scope_data = ContentLibraryData(external_key=str(self.library_key))
        scope = Scope.objects.get_or_create_for_external_key(scope_data)

        casbin_rule = CasbinRule.objects.create(
            ptype="p",
            v0=subject_data.namespaced_key,
            v1="role^instructor",
            v2=scope_data.namespaced_key,
            v3="allow",
        )

        casbin_rule_key = f"{casbin_rule.ptype},{casbin_rule.v0},{casbin_rule.v1},{casbin_rule.v2},{casbin_rule.v3}"
        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key,
            casbin_rule=casbin_rule,
            subject=subject,
            scope=scope,
        )
        extended_rule_id = extended_rule.id

        self.assertTrue(ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists())

        casbin_rule.delete()

        self.assertFalse(
            ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists()
        )
        self.assertTrue(Subject.objects.filter(id=subject.id).exists())
        self.assertTrue(Scope.objects.filter(id=scope.id).exists())
        self.assertTrue(User.objects.filter(id=self.test_user.id).exists())
        self.assertTrue(
            ContentLibrary.objects.filter(id=self.content_library.id).exists()
        )
