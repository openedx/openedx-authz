"""Test cases for authorization models.

This test suite verifies the functionality of the authorization models including:
- Scope model with ContentLibrary integration
- Subject model with User integration
- ExtendedCasbinRule model with metadata and relationships
- Cascade deletion behavior

Note: These tests require ContentLibrary model to be available in the environment.
Run these tests in an environment where openedx.core.djangoapps.content_libraries.models
is accessible (e.g., edx-platform with content libraries installed).
"""

from casbin_adapter.models import CasbinRule
from ddt import data as ddt_data, ddt, unpack
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import TestCase
from opaque_keys.edx.locator import LibraryLocatorV2
from organizations.api import ensure_organization
from unittest.mock import Mock

from openedx.core.djangoapps.content_libraries import api as library_api
from openedx.core.djangoapps.content_libraries.models import ContentLibrary
from openedx_authz.api.data import ContentLibraryData, RoleData, ScopeData, SubjectData, UserData
from openedx_authz.engine.filter import Filter
from openedx_authz.models import ExtendedCasbinRule, Scope, Subject

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
    import uuid
    from organizations.models import Organization

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
class TestScopeModel(TestCase):
    """Test cases for the Scope model."""

    def setUp(self):
        """Set up test fixtures."""
        # Create library using the API helper (auto-generates unique slug)
        self.library_metadata, self.library_key, self.content_library = create_test_library(
            org_short_name="TestOrg",
        )

    def test_get_or_create_scope_for_content_library_creates_new(self):
        """Test that get_or_create_scope_for_content_library creates a new Scope when none exists.

        Expected result:
            - Scope is created successfully
            - Scope is linked to the ContentLibrary
            - Only one Scope exists for the ContentLibrary
        """
        scope_data = ContentLibraryData(external_key=str(self.library_key))

        scope = Scope.get_or_create_scope_for_content_library(scope_data.external_key)

        self.assertIsNotNone(scope)
        self.assertEqual(scope.content_library, self.content_library)
        self.assertEqual(Scope.objects.filter(content_library=self.content_library).count(), 1)

    def test_get_or_create_scope_for_content_library_gets_existing(self):
        """Test that get_or_create_scope_for_content_library retrieves existing Scope.

        Expected result:
            - First call creates the Scope
            - Second call retrieves the same Scope
            - Only one Scope exists for the ContentLibrary
        """
        scope_data = ContentLibraryData(external_key=str(self.library_key))

        scope1 = Scope.get_or_create_scope_for_content_library(scope_data.external_key)
        scope2 = Scope.get_or_create_scope_for_content_library(scope_data.external_key)

        self.assertEqual(scope1.id, scope2.id)
        self.assertEqual(Scope.objects.filter(content_library=self.content_library).count(), 1)

    def test_scope_can_be_created_without_content_library(self):
        """Test that Scope can be created without a content_library.

        Expected result:
            - Scope is created successfully
            - content_library field is None
        """
        scope = Scope.objects.create(content_library=None)

        self.assertIsNotNone(scope)
        self.assertIsNone(scope.content_library)

    def test_scope_cascade_deletion_when_content_library_deleted(self):
        """Test that Scope is deleted when its ContentLibrary is deleted.

        Expected result:
            - Scope is created successfully
            - Deleting ContentLibrary also deletes the Scope
        """
        scope_data = ContentLibraryData(external_key=str(self.library_key))
        scope = Scope.get_or_create_scope_for_content_library(scope_data.external_key)
        scope_id = scope.id

        self.content_library.delete()

        self.assertFalse(Scope.objects.filter(id=scope_id).exists())


@ddt
class TestSubjectModel(TestCase):
    """Test cases for the Subject model."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_username = "test_user"
        self.test_user = User.objects.create_user(username=self.test_username)

    def test_get_or_create_subject_for_user_creates_new(self):
        """Test that get_or_create_subject_for_user creates a new Subject when none exists.

        Expected result:
            - Subject is created successfully
            - Subject is linked to the User
            - Only one Subject exists for the User
        """
        subject_data = UserData(external_key=self.test_username)

        subject = Subject.get_or_create_subject_for_user(subject_data.external_key)

        self.assertIsNotNone(subject)
        self.assertEqual(subject.user, self.test_user)
        self.assertEqual(Subject.objects.filter(user=self.test_user).count(), 1)

    def test_get_or_create_subject_for_user_gets_existing(self):
        """Test that get_or_create_subject_for_user retrieves existing Subject.

        Expected result:
            - First call creates the Subject
            - Second call retrieves the same Subject
            - Only one Subject exists for the User
        """
        subject_data = UserData(external_key=self.test_username)

        subject1 = Subject.get_or_create_subject_for_user(subject_data.external_key)
        subject2 = Subject.get_or_create_subject_for_user(subject_data.external_key)

        self.assertEqual(subject1.id, subject2.id)
        self.assertEqual(Subject.objects.filter(user=self.test_user).count(), 1)

    def test_subject_can_be_created_without_user(self):
        """Test that Subject can be created without a user.

        Expected result:
            - Subject is created successfully
            - user field is None
        """
        subject = Subject.objects.create(user=None)

        self.assertIsNotNone(subject)
        self.assertIsNone(subject.user)

    def test_subject_cascade_deletion_when_user_deleted(self):
        """Test that Subject is deleted when its User is deleted.

        Expected result:
            - Subject is created successfully
            - Deleting User also deletes the Subject
        """
        subject_data = UserData(external_key=self.test_username)
        subject = Subject.get_or_create_subject_for_user(subject_data.external_key)
        subject_id = subject.id

        self.test_user.delete()

        self.assertFalse(Subject.objects.filter(id=subject_id).exists())


@ddt
class TestExtendedCasbinRuleModel(TestCase):
    """Test cases for the ExtendedCasbinRule model."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_username = "test_user"
        self.test_user = User.objects.create_user(username=self.test_username)

        # Create library using the API helper (auto-generates unique slug)
        self.library_metadata, self.library_key, self.content_library = create_test_library(
            org_short_name="TestOrg",
        )

        self.casbin_rule = CasbinRule.objects.create(
            ptype="p",
            v0="user^test_user",
            v1="role^instructor",
            v2="lib^lib:TestOrg:TestLib",
            v3="allow"
        )

        self.subject = Subject.objects.create(user=self.test_user)

        scope_data = ContentLibraryData(external_key=str(self.library_key))
        self.scope = Scope.get_or_create_scope_for_content_library(scope_data.external_key)

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
            subject=self.subject
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
            casbin_rule_key=casbin_rule_key,
            casbin_rule=self.casbin_rule
        )

        casbin_rule2 = CasbinRule.objects.create(
            ptype="p",
            v0="user^test_user2",
            v1="role^admin",
            v2="lib^lib:TestOrg:TestLib2",
            v3="allow"
        )

        with self.assertRaises(IntegrityError):
            ExtendedCasbinRule.objects.create(
                casbin_rule_key=casbin_rule_key,
                casbin_rule=casbin_rule2
            )

    def test_extended_casbin_rule_cascade_deletion_when_casbin_rule_deleted(self):
        """Test that ExtendedCasbinRule is deleted when its CasbinRule is deleted.

        Expected result:
            - ExtendedCasbinRule is created successfully
            - Deleting CasbinRule also deletes the ExtendedCasbinRule
        """
        casbin_rule_key = f"{self.casbin_rule.ptype},{self.casbin_rule.v0},{self.casbin_rule.v1},{self.casbin_rule.v2},{self.casbin_rule.v3}"
        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key,
            casbin_rule=self.casbin_rule
        )
        extended_rule_id = extended_rule.id

        self.casbin_rule.delete()

        self.assertFalse(ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists())

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
            scope=self.scope
        )
        extended_rule_id = extended_rule.id

        self.scope.delete()

        self.assertFalse(ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists())

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
            subject=self.subject
        )
        extended_rule_id = extended_rule.id

        self.subject.delete()

        self.assertFalse(ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists())

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
                "features": ["read", "write", "delete"]
            },
            "audit": {
                "created_by": "system",
                "last_modified_by": "admin"
            }
        }

        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key,
            casbin_rule=self.casbin_rule,
            metadata=complex_metadata
        )

        retrieved_rule = ExtendedCasbinRule.objects.get(id=extended_rule.id)

        self.assertEqual(retrieved_rule.metadata["tags"], ["test", "instructor", "library"])
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
        self.assertEqual(ExtendedCasbinRule._meta.verbose_name_plural, "Extended Casbin Rules")

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
            v3="allow"
        )

        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key,
            casbin_rule=casbin_rule2
        )

        self.assertIsNotNone(extended_rule)
        self.assertIsNone(extended_rule.description)
        self.assertIsNone(extended_rule.metadata)
        self.assertIsNone(extended_rule.scope)
        self.assertIsNone(extended_rule.subject)


@ddt
class TestExtendedCasbinRuleCreateBasedOnPolicy(TestCase):
    """Test cases for ExtendedCasbinRule.create_based_on_policy method.

    Note: These tests use a mock enforcer to avoid dependencies on the full
    enforcer infrastructure. For integration tests with a real enforcer,
    see the integration test suite.
    """

    def setUp(self):
        """Set up test fixtures."""
        self.test_username = "test_user"
        self.test_user = User.objects.create_user(username=self.test_username)

        # Create library using the API helper (auto-generates unique slug)
        self.library_metadata, self.library_key, self.content_library = create_test_library(
            org_short_name="TestOrg",
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

        subject = Subject.objects.create(user=self.test_user)
        scope = Scope.get_or_create_scope_for_content_library(scope_data.external_key)

        casbin_rule = CasbinRule.objects.create(
            ptype="p",
            v0=subject_data.namespaced_key,
            v1=role_data.namespaced_key,
            v2=scope_data.namespaced_key,
            v3="allow"
        )

        mock_enforcer = Mock()
        mock_enforcer.query_policy.return_value = casbin_rule

        expected_key = f"p,{subject_data.namespaced_key},{role_data.namespaced_key},{scope_data.namespaced_key},allow"

        extended_rule_instance = ExtendedCasbinRule()
        result = extended_rule_instance.create_based_on_policy(
            subject_external_key=subject_data.external_key,
            role_external_key=role_data.external_key,
            scope_external_key=scope_data.external_key,
            enforcer=mock_enforcer
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

        subject = Subject.objects.create(user=self.test_user)
        scope = Scope.get_or_create_scope_for_content_library(scope_data.external_key)

        casbin_rule = CasbinRule.objects.create(
            ptype="p",
            v0=subject_data.namespaced_key,
            v1=role_data.namespaced_key,
            v2=scope_data.namespaced_key,
            v3="allow"
        )

        mock_enforcer = Mock()
        mock_enforcer.query_policy.return_value = casbin_rule

        extended_rule_instance1 = ExtendedCasbinRule()
        result1 = extended_rule_instance1.create_based_on_policy(
            subject_external_key=subject_data.external_key,
            role_external_key=role_data.external_key,
            scope_external_key=scope_data.external_key,
            enforcer=mock_enforcer
        )

        extended_rule_instance2 = ExtendedCasbinRule()
        result2 = extended_rule_instance2.create_based_on_policy(
            subject_external_key=subject_data.external_key,
            role_external_key=role_data.external_key,
            scope_external_key=scope_data.external_key,
            enforcer=mock_enforcer
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

        Subject.objects.create(user=self.test_user)
        Scope.get_or_create_scope_for_content_library(scope_data.external_key)

        casbin_rule = CasbinRule.objects.create(
            ptype="p",
            v0=subject_data.namespaced_key,
            v1=role_data.namespaced_key,
            v2=scope_data.namespaced_key,
            v3="allow"
        )

        mock_enforcer = Mock()
        mock_enforcer.query_policy.return_value = casbin_rule

        extended_rule_instance = ExtendedCasbinRule()
        extended_rule_instance.create_based_on_policy(
            subject_external_key=subject_data.external_key,
            role_external_key=role_data.external_key,
            scope_external_key=scope_data.external_key,
            enforcer=mock_enforcer
        )

        mock_enforcer.query_policy.assert_called_once()
        call_args = mock_enforcer.query_policy.call_args[0][0]
        self.assertIsInstance(call_args, Filter)


@ddt
class TestModelRelationships(TestCase):
    """Test cases for model relationships and related_name attributes."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_username = "test_user"
        self.test_user = User.objects.create_user(username=self.test_username)
        self.subject = Subject.objects.create(user=self.test_user)

        # Create library using the API helper (auto-generates unique slug)
        self.library_metadata, self.library_key, self.content_library = create_test_library(
            org_short_name="TestOrg",
        )

        self.casbin_rule = CasbinRule.objects.create(
            ptype="p",
            v0="user^test_user",
            v1="role^instructor",
            v2="lib^lib:TestOrg:TestLib",
            v3="allow"
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
            subject=self.subject
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
        scope = Scope.get_or_create_scope_for_content_library(scope_data.external_key)

        casbin_rule_key = f"{self.casbin_rule.ptype},{self.casbin_rule.v0},{self.casbin_rule.v1},{self.casbin_rule.v2},{self.casbin_rule.v3}"
        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key,
            casbin_rule=self.casbin_rule,
            scope=scope
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
            casbin_rule_key=casbin_rule_key,
            casbin_rule=self.casbin_rule
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
        scope = Scope.get_or_create_scope_for_content_library(scope_data.external_key)

        self.assertEqual(self.content_library.authz_scopes.count(), 1)
        self.assertEqual(self.content_library.authz_scopes.first(), scope)


@ddt
class TestModelCascadeDeletionChain(TestCase):
    """Test cases for cascade deletion chains across multiple models."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_username = "test_user"
        self.test_user = User.objects.create_user(username=self.test_username)

        # Create library using the API helper (auto-generates unique slug)
        self.library_metadata, self.library_key, self.content_library = create_test_library(
            org_short_name="TestOrg",
        )

    def test_content_library_deletion_cascades_to_extended_casbin_rules(self):
        """Test that deleting ContentLibrary cascades through Scope to ExtendedCasbinRule.

        Expected result:
            - Deleting ContentLibrary deletes the Scope
            - Deleting Scope cascades to delete ExtendedCasbinRule
        """
        scope_data = ContentLibraryData(external_key=str(self.library_key))
        scope = Scope.get_or_create_scope_for_content_library(scope_data.external_key)

        casbin_rule = CasbinRule.objects.create(
            ptype="p",
            v0="user^test_user",
            v1="role^instructor",
            v2=scope_data.namespaced_key,
            v3="allow"
        )

        casbin_rule_key = f"{casbin_rule.ptype},{casbin_rule.v0},{casbin_rule.v1},{casbin_rule.v2},{casbin_rule.v3}"
        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key,
            casbin_rule=casbin_rule,
            scope=scope
        )
        extended_rule_id = extended_rule.id

        self.content_library.delete()

        self.assertFalse(Scope.objects.filter(id=scope.id).exists())
        self.assertFalse(ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists())

    def test_user_deletion_cascades_to_extended_casbin_rules(self):
        """Test that deleting User cascades through Subject to ExtendedCasbinRule.

        Expected result:
            - Deleting User deletes the Subject
            - Deleting Subject cascades to delete ExtendedCasbinRule
        """
        subject_data = UserData(external_key=self.test_username)
        subject = Subject.get_or_create_subject_for_user(subject_data.external_key)

        casbin_rule = CasbinRule.objects.create(
            ptype="p",
            v0=subject_data.namespaced_key,
            v1="role^instructor",
            v2="lib^lib:TestOrg:TestLib",
            v3="allow"
        )

        casbin_rule_key = f"{casbin_rule.ptype},{casbin_rule.v0},{casbin_rule.v1},{casbin_rule.v2},{casbin_rule.v3}"
        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key,
            casbin_rule=casbin_rule,
            subject=subject
        )
        extended_rule_id = extended_rule.id

        self.test_user.delete()

        self.assertFalse(Subject.objects.filter(id=subject.id).exists())
        self.assertFalse(ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists())

    def test_complete_cascade_deletion_chain(self):
        """Test complete cascade deletion with all models linked together.

        Expected result:
            - Deleting CasbinRule deletes ExtendedCasbinRule
            - Subject and Scope remain after ExtendedCasbinRule deletion
            - User and ContentLibrary remain after ExtendedCasbinRule deletion
        """
        subject_data = UserData(external_key=self.test_username)
        subject = Subject.get_or_create_subject_for_user(subject_data.external_key)

        scope_data = ContentLibraryData(external_key=str(self.library_key))
        scope = Scope.get_or_create_scope_for_content_library(scope_data.external_key)

        casbin_rule = CasbinRule.objects.create(
            ptype="p",
            v0=subject_data.namespaced_key,
            v1="role^instructor",
            v2=scope_data.namespaced_key,
            v3="allow"
        )

        casbin_rule_key = f"{casbin_rule.ptype},{casbin_rule.v0},{casbin_rule.v1},{casbin_rule.v2},{casbin_rule.v3}"
        extended_rule = ExtendedCasbinRule.objects.create(
            casbin_rule_key=casbin_rule_key,
            casbin_rule=casbin_rule,
            subject=subject,
            scope=scope
        )
        extended_rule_id = extended_rule.id

        self.assertTrue(ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists())

        casbin_rule.delete()

        self.assertFalse(ExtendedCasbinRule.objects.filter(id=extended_rule_id).exists())
        self.assertTrue(Subject.objects.filter(id=subject.id).exists())
        self.assertTrue(Scope.objects.filter(id=scope.id).exists())
        self.assertTrue(User.objects.filter(id=self.test_user.id).exists())
        self.assertTrue(ContentLibrary.objects.filter(id=self.content_library.id).exists())
