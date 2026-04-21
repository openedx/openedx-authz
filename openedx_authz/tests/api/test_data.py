"""Test data for the authorization API."""

from unittest.mock import Mock, patch

from ddt import data, ddt, unpack
from django.test import TestCase
from opaque_keys.edx.locator import LibraryLocatorV2

from openedx_authz.api.data import (
    ActionData,
    CCXCourseOverviewData,
    ContentLibraryData,
    CourseOverviewData,
    GlobalWildcardScopeData,
    OrgContentLibraryGlobData,
    OrgCourseOverviewGlobData,
    PermissionData,
    RoleAssignmentData,
    RoleData,
    ScopeData,
    ScopeMeta,
    SubjectData,
    UserData,
)
from openedx_authz.constants import permissions, roles
from openedx_authz.tests.stubs.models import ContentLibrary, CourseOverview, Organization


@ddt
class TestNamespacedData(TestCase):
    """Test data for the authorization API."""

    @data(
        ("instructor",),
        ("admin",),
    )
    @unpack
    def test_role_data_namespace(self, external_key):
        """Test that RoleData correctly namespaces role names.

        Expected Result:
            - If input is 'instructor', expected is 'role^instructor'
            - If input is 'admin', expected is 'role^admin'
        """
        role = RoleData(external_key=external_key)

        expected = f"{role.NAMESPACE}{role.SEPARATOR}{external_key}"

        self.assertEqual(role.namespaced_key, expected)

    @data(
        ("john_doe",),
        ("jane_smith",),
    )
    @unpack
    def test_user_data_namespace(self, external_key):
        """Test that UserData correctly namespaces user IDs.

        Expected Result:
            - If input is 'john_doe', expected is 'user^john_doe'
            - If input is 'jane_smith', expected is 'user^jane_smith'
        """
        user = UserData(external_key=external_key)

        expected = f"{user.NAMESPACE}{user.SEPARATOR}{external_key}"

        self.assertEqual(user.namespaced_key, expected)

    @data(
        ("read",),
        ("write",),
    )
    @unpack
    def test_action_data_namespace(self, external_key):
        """Test that ActionData correctly namespaces action IDs.

        Expected Result:
            - If input is 'read', expected is 'act^read'
            - If input is 'write', expected is 'act^write'
        """
        action = ActionData(external_key=external_key)

        expected = f"{action.NAMESPACE}{action.SEPARATOR}{external_key}"

        self.assertEqual(action.namespaced_key, expected)

    @data(
        ("lib:DemoX:CSPROB",),
    )
    @unpack
    def test_scope_content_lib_data_namespace(self, external_key):
        """Test that ContentLibraryData correctly namespaces library IDs.

        Expected Result:
            - If input is 'lib:DemoX:CSPROB', expected is 'lib^lib:DemoX:CSPROB'
        """
        scope = ContentLibraryData(external_key=external_key)

        expected = f"{scope.NAMESPACE}{scope.SEPARATOR}{external_key}"

        self.assertEqual(scope.namespaced_key, expected)

    @data(
        ("lib:DemoX:CSPROB", "DemoX"),
        ("lib:Org1:math_101", "Org1"),
    )
    @unpack
    def test_content_library_data_org_property(self, external_key, expected_org):
        """Test that ContentLibraryData returns the correct organization name."""
        scope = ContentLibraryData(external_key=external_key)

        self.assertEqual(scope.org, expected_org)

    @data(
        ("course-v1:DemoX+TestCourse+2024_T1", "DemoX"),
        ("course-v1:WGU+CS002+2025_T1", "WGU"),
    )
    @unpack
    def test_course_overview_data_org_property(self, external_key, expected_org):
        """Test that CourseOverviewData returns the correct organization name."""
        scope = CourseOverviewData(external_key=external_key)

        self.assertEqual(scope.org, expected_org)


@ddt
class TestPolymorphicData(TestCase):
    """Test polymorphic factory pattern for SubjectData and ScopeData."""

    @data(
        ("john_doe",),
        ("jane_smith",),
    )
    @unpack
    def test_user_data_with_namespaced_key(self, external_key):
        """Test that UserData can be instantiated with namespaced_key.

        Expected Result:
            - UserData(namespaced_key='user^john_doe') creates UserData instance
        """
        namespaced_key = f"{UserData.NAMESPACE}{UserData.SEPARATOR}{external_key}"

        user = UserData(namespaced_key=namespaced_key)

        self.assertIsInstance(user, UserData)
        self.assertEqual(user.namespaced_key, namespaced_key)
        self.assertEqual(user.external_key, external_key)

    def test_subject_data_direct_instantiation_with_namespaced_key(self):
        """Test that SubjectData can be instantiated with namespaced_key.

        Expected Result:
            - SubjectData(namespaced_key='sub^generic') creates SubjectData instance
        """
        namespaced_key = f"{SubjectData.NAMESPACE}{SubjectData.SEPARATOR}generic"

        subject = SubjectData(namespaced_key=namespaced_key)

        self.assertIsInstance(subject, SubjectData)
        self.assertEqual(subject.namespaced_key, namespaced_key)
        self.assertEqual(subject.external_key, "generic")

    @data(
        ("math_101",),
        ("science_201",),
    )
    @unpack
    def test_content_library_data_with_namespaced_key(self, external_key):
        """Test that ContentLibraryData can be instantiated with namespaced_key.

        Expected Result:
            - ContentLibraryData(namespaced_key='lib^math_101') creates ContentLibraryData instance
        """
        namespaced_key = f"{ContentLibraryData.NAMESPACE}{ContentLibraryData.SEPARATOR}{external_key}"

        library = ContentLibraryData(namespaced_key=namespaced_key)

        self.assertIsInstance(library, ContentLibraryData)
        self.assertEqual(library.namespaced_key, namespaced_key)
        self.assertEqual(library.external_key, external_key)

    def test_scope_data_direct_instantiation_with_namespaced_key(self):
        """Test that ScopeData can be instantiated with namespaced_key.

        Expected Result:
            - ScopeData(namespaced_key='global^generic') creates ScopeData instance
        """
        namespaced_key = f"{ScopeData.NAMESPACE}{ScopeData.SEPARATOR}generic"

        scope = ScopeData(namespaced_key=namespaced_key)

        self.assertIsInstance(scope, ScopeData)
        self.assertEqual(scope.namespaced_key, namespaced_key)
        self.assertEqual(scope.external_key, "generic")

    def test_user_data_direct_instantiation(self):
        """Test that UserData can be instantiated directly.

        Expected Result:
            - UserData(external_key='alice') creates UserData instance
        """
        user = UserData(external_key="alice")

        expected_namespaced = f"{user.NAMESPACE}{user.SEPARATOR}alice"

        self.assertIsInstance(user, UserData)
        self.assertEqual(user.namespaced_key, expected_namespaced)
        self.assertEqual(user.external_key, "alice")

    def test_content_library_direct_instantiation(self):
        """Test that ContentLibraryData can be instantiated directly.

        Expected Result:
            - ContentLibraryData(external_key='lib:Demo:CS') creates ContentLibraryData instance
        """
        library = ContentLibraryData(external_key="lib:demo:cs")

        expected_namespaced = f"{library.NAMESPACE}{library.SEPARATOR}lib:demo:cs"

        self.assertIsInstance(library, ContentLibraryData)
        self.assertEqual(library.namespaced_key, expected_namespaced)
        self.assertEqual(library.external_key, "lib:demo:cs")

    @data(
        ("lib:math_101",),
        ("lib:DemoX:CSPROB",),
    )
    @unpack
    def test_content_library_data_with_external_key(self, external_key):
        """Test that ContentLibraryData with external_key generates correct namespaced_key.

        Expected Result:
            - ContentLibraryData(external_key='lib:math_101') creates ContentLibraryData instance
            - namespaced_key is 'lib^lib:math_101'
        """
        library = ContentLibraryData(external_key=external_key)

        expected_namespaced_key = f"{library.NAMESPACE}{library.SEPARATOR}{external_key}"

        self.assertIsInstance(library, ContentLibraryData)
        self.assertEqual(library.external_key, external_key)
        self.assertEqual(library.namespaced_key, expected_namespaced_key)


@ddt
class TestScopeMetaClass(TestCase):
    """Test the ScopeMeta metaclass functionality."""

    def test_scope_data_registration(self):
        """Test that ScopeData and its subclasses are registered correctly.

        Expected Result:
            - 'global' namespace maps to ScopeData class in scope_registry
            - 'global' namespace maps to GlobalWildcardScopeData in glob_registry
            - 'lib' namespace maps to ContentLibraryData class
        """
        self.assertIn("global", ScopeData.scope_registry)
        self.assertIs(ScopeData.scope_registry["global"], ScopeData)
        self.assertIn("lib", ScopeData.scope_registry)
        self.assertIs(ScopeData.scope_registry["lib"], ContentLibraryData)
        self.assertIn("course-v1", ScopeData.scope_registry)
        self.assertIs(ScopeData.scope_registry["course-v1"], CourseOverviewData)
        self.assertIn("ccx-v1", ScopeData.scope_registry)
        self.assertIs(ScopeData.scope_registry["ccx-v1"], CCXCourseOverviewData)

        # Glob registries for organization-level scopes and global wildcard
        self.assertIn("global", ScopeMeta.glob_registry)
        self.assertIs(ScopeMeta.glob_registry["global"], GlobalWildcardScopeData)
        self.assertIn("lib", ScopeMeta.glob_registry)
        self.assertIs(ScopeMeta.glob_registry["lib"], OrgContentLibraryGlobData)
        self.assertIn("course-v1", ScopeMeta.glob_registry)
        self.assertIs(ScopeMeta.glob_registry["course-v1"], OrgCourseOverviewGlobData)

    @data(
        ("ccx-v1^ccx-v1:OpenedX+DemoX+DemoCourse+ccx@1", CCXCourseOverviewData),
        ("course-v1^course-v1:WGU+CS002+2025_T1", CourseOverviewData),
        ("lib^lib:DemoX:CSPROB", ContentLibraryData),
        ("lib^lib:DemoX*", OrgContentLibraryGlobData),
        ("course-v1^course-v1:OpenedX*", OrgCourseOverviewGlobData),
        ("global^generic_scope", ScopeData),
    )
    @unpack
    def test_dynamic_instantiation_via_namespaced_key(self, namespaced_key, expected_class):
        """Test that ScopeData dynamically instantiates the correct subclass.

        Expected Result:
            - ScopeData(namespaced_key='lib^...') returns ContentLibraryData instance
            - ScopeData(namespaced_key='global^...') returns ScopeData instance
        """
        instance = ScopeData(namespaced_key=namespaced_key)

        self.assertIsInstance(instance, expected_class)
        self.assertEqual(instance.namespaced_key, namespaced_key)

    @data(
        ("ccx-v1^ccx-v1:OpenedX+DemoX+DemoCourse+ccx@1", CCXCourseOverviewData),
        ("course-v1^course-v1:WGU+CS002+2025_T1", CourseOverviewData),
        ("lib^lib:DemoX:CSPROB", ContentLibraryData),
        ("lib^lib:DemoX:*", OrgContentLibraryGlobData),
        ("course-v1^course-v1:OpenedX+*", OrgCourseOverviewGlobData),
        ("global^generic", ScopeData),
        ("unknown^something", ScopeData),
    )
    @unpack
    def test_get_subclass_by_namespaced_key(self, namespaced_key, expected_class):
        """Test get_subclass_by_namespaced_key returns correct subclass.

        Expected Result:
            - 'ccx-v1^...' returns CCXCourseOverviewData
            - 'course-v1^...' returns CourseOverviewData
            - 'lib^...' returns ContentLibraryData
            - 'global^...' returns ScopeData
            - 'unknown^...' returns ScopeData (fallback)
        """
        subclass = ScopeMeta.get_subclass_by_namespaced_key(namespaced_key)

        self.assertIs(subclass, expected_class)

    @data(
        ("ccx-v1:OpenedX+DemoX+DemoCourse+ccx@1", CCXCourseOverviewData),
        ("course-v1:WGU+CS002+2025_T1", CourseOverviewData),
        ("lib:DemoX:CSPROB", ContentLibraryData),
        ("lib:DemoX:*", OrgContentLibraryGlobData),
        ("course-v1:OpenedX+*", OrgCourseOverviewGlobData),
        ("lib:edX:Demo", ContentLibraryData),
        ("global:generic_scope", ScopeData),
        ("*", GlobalWildcardScopeData),
    )
    @unpack
    def test_get_subclass_by_external_key(self, external_key, expected_class):
        """Test get_subclass_by_external_key returns correct subclass.

        Expected Result:
            - 'lib:...' returns ContentLibraryData
            - 'global:...' returns ScopeData
        """
        subclass = ScopeMeta.get_subclass_by_external_key(external_key)

        self.assertIs(subclass, expected_class)

    @data(
        ("ccx-v1:OpenedX+DemoX+DemoCourse+ccx@1", True, CCXCourseOverviewData),
        ("ccx:OpenedX+DemoX+DemoCourse+ccx@1", False, CCXCourseOverviewData),
        ("ccx-v2:OpenedX+DemoX+DemoCourse+ccx@1", False, CCXCourseOverviewData),
        ("ccx-v1-OpenedX+DemoX+DemoCourse+ccx@1", False, CCXCourseOverviewData),
        ("ccx-v1-OpenedX+DemoX+DemoCourse+ccx", False, CCXCourseOverviewData),
        ("course-v1:WGU+CS002+2025_T1", True, CourseOverviewData),
        ("course:WGU+CS002+2025_T1", False, CourseOverviewData),
        ("course-v2:WGU+CS002+2025_T1", False, CourseOverviewData),
        ("course-v1-WGU+CS002+2025_T1", False, CourseOverviewData),
        ("lib:DemoX:CSPROB", True, ContentLibraryData),
        ("lib:edX:Demo", True, ContentLibraryData),
        ("invalid_library_key", False, ContentLibraryData),
        ("lib-DemoX-CSPROB", False, ContentLibraryData),
    )
    @unpack
    def test_scope_validate_external_key(self, external_key, expected_valid, expected_class):
        """Test Subclasses ScopeData.validate_external_key validates library keys.

        Expected Result:
            - Valid Scope keys like (lib:Org:Code) return True
            - Invalid formats return False
        """
        result = expected_class.validate_external_key(external_key)

        self.assertEqual(result, expected_valid)

    @data(
        "unknown:DemoX",
        "unknown:DemoX:*",
    )
    def test_get_subclass_by_external_key_unknown_scope_raises_value_error(self, external_key):
        """Inknown namespace should raise ValueError, including wildcard keys."""
        with self.assertRaises(ValueError):
            ScopeMeta.get_subclass_by_external_key(external_key)

    @data(
        "lib:invalid_library_key",
        "lib:DemoX:slug*",
        "course-v1:OpenedX+CS101+*",
    )
    def test_get_subclass_by_external_key_invalid_format_raises_value_error(self, external_key):
        """Invalid format should raise ValueError for regular and wildcard keys."""
        with self.assertRaises(ValueError):
            ScopeMeta.get_subclass_by_external_key(external_key)

    def test_scope_meta_initializes_registries_when_missing(self):
        """ScopeMeta should create registries if they don't exist on initialization.

        This validates the defensive branch in ScopeMeta.__init__ that initializes
        scope_registry and glob_registry when they are not present on the class.
        """
        original_scope_registry = ScopeMeta.scope_registry
        original_glob_registry = ScopeMeta.glob_registry

        try:
            # Simulate an environment where the registries are not yet defined
            del ScopeMeta.scope_registry
            del ScopeMeta.glob_registry

            class TempScope(ScopeData):
                """Temporary scope class for testing."""

                NAMESPACE = "temp"

                def get_object(self):
                    return None

                def exists(self) -> bool:
                    return False

                @classmethod
                def get_admin_view_permission(cls):
                    raise NotImplementedError("Not implemented for TempScope")

            # Metaclass should have recreated the registries on the class
            self.assertTrue(hasattr(TempScope, "scope_registry"))
            self.assertTrue(hasattr(TempScope, "glob_registry"))
            # And the new scope should be registered under its namespace
            self.assertIs(TempScope.scope_registry.get("temp"), TempScope)
        finally:
            # Restore original registries to avoid side effects on other tests
            ScopeMeta.scope_registry = original_scope_registry
            ScopeMeta.glob_registry = original_glob_registry

    def test_direct_subclass_instantiation_bypasses_metaclass(self):
        """Test that direct subclass instantiation doesn't trigger metaclass logic.

        Expected Result:
            - ContentLibraryData(external_key='...') creates ContentLibraryData directly
            - No metaclass dynamic instantiation occurs
        """
        library = ContentLibraryData(external_key="lib:Demo:CS")

        self.assertIsInstance(library, ContentLibraryData)
        self.assertEqual(library.external_key, "lib:Demo:CS")

    def test_base_scope_data_with_external_key(self):
        """Test ScopeData instantiation with external_key (not namespaced_key).

        Expected Result:
            - ScopeData(external_key='...') creates ScopeData instance
            - No dynamic subclass selection occurs
        """
        scope = ScopeData(external_key="global:generic_scope")

        expected_namespaced = f"{ScopeData.NAMESPACE}{ScopeData.SEPARATOR}global:generic_scope"

        self.assertIsInstance(scope, ScopeData)
        self.assertEqual(scope.external_key, "global:generic_scope")
        self.assertEqual(scope.namespaced_key, expected_namespaced)

    def test_empty_namespaced_key_raises_value_error(self):
        """Test that providing an empty namespaced_key raises ValueError.

        Expected Result:
            - ValueError is raised
        """
        with self.assertRaises(ValueError):
            ScopeData(namespaced_key="")

    def test_empty_external_key_raises_value_error(self):
        """Test that providing an empty external_key raises ValueError.

        Expected Result:
            - ValueError is raised
        """
        with self.assertRaises(ValueError):
            SubjectData(external_key="")

    def test_scope_data_with_wildcard_external_key(self):
        """Test that ScopeData instantiated with wildcard (*) returns GlobalWildcardScopeData.

        When using the global scope wildcard '*', the metaclass should return a
        GlobalWildcardScopeData instance rather than attempting subclass determination
        from the external_key format.

        Expected Result:
            - ScopeData(external_key='*') creates GlobalWildcardScopeData instance
            - namespaced_key is 'global^*'
            - exists() returns True
            - get_object() returns None
        """
        scope = ScopeData(external_key="*")

        expected_namespaced = f"{GlobalWildcardScopeData.NAMESPACE}{GlobalWildcardScopeData.SEPARATOR}*"

        self.assertIsInstance(scope, ScopeData)
        self.assertIsInstance(scope, GlobalWildcardScopeData)
        self.assertEqual(scope.external_key, "*")
        self.assertEqual(scope.namespaced_key, expected_namespaced)
        self.assertTrue(scope.exists())
        self.assertIsNone(scope.get_object())


@ddt
class TestDataRepresentation(TestCase):
    """Test the string representations of data classes."""

    @data(
        ("john_doe", "john_doe", "user^john_doe"),
        ("jane_smith", "jane_smith", "user^jane_smith"),
    )
    @unpack
    def test_user_data_str_and_repr(self, external_key, expected_str, expected_repr):
        """Test UserData __str__ and __repr__ methods.

        Expected Result:
            - __str__ returns the username (external_key)
            - __repr__ returns the namespaced_key
        """
        user = UserData(external_key=external_key)

        actual_str = str(user)
        actual_repr = repr(user)

        self.assertEqual(actual_str, expected_str)
        self.assertEqual(actual_repr, expected_repr)

    @data(
        ("read", "Read", "act^read"),
        ("write", "Write", "act^write"),
        (
            permissions.DELETE_LIBRARY.identifier,
            "Content Libraries > Delete Library",
            "act^content_libraries.delete_library",
        ),
        ("edit_content", "Edit Content", "act^edit_content"),
    )
    @unpack
    def test_action_data_str_and_repr(self, external_key, expected_str, expected_repr):
        """Test ActionData __str__ and __repr__ methods.

        Expected Result:
            - __str__ returns the human-readable name (title case with spaces)
            - __repr__ returns the namespaced_key
        """
        action = ActionData(external_key=external_key)

        actual_str = str(action)
        actual_repr = repr(action)

        self.assertEqual(actual_str, expected_str)
        self.assertEqual(actual_repr, expected_repr)

    @data(
        ("lib:DemoX:CSPROB", "lib:DemoX:CSPROB", "lib^lib:DemoX:CSPROB"),
        ("lib:edX:Demo", "lib:edX:Demo", "lib^lib:edX:Demo"),
    )
    @unpack
    def test_scope_data_str_and_repr(self, external_key, expected_str, expected_repr):
        """Test ScopeData __str__ and __repr__ methods.

        Expected Result:
            - __str__ returns the external_key
            - __repr__ returns the namespaced_key
        """
        scope = ContentLibraryData(external_key=external_key)

        actual_str = str(scope)
        actual_repr = repr(scope)

        self.assertEqual(actual_str, expected_str)
        self.assertEqual(actual_repr, expected_repr)

    @data(
        ("instructor", "Instructor", "role^instructor"),
        (roles.LIBRARY_ADMIN.external_key, "Library Admin", "role^library_admin"),
        ("course_staff", "Course Staff", "role^course_staff"),
    )
    @unpack
    def test_role_data_str_without_permissions(self, external_key, expected_name, expected_repr):
        """Test RoleData __str__ and __repr__ methods without permissions.

        Expected Result:
            - __str__ returns the role name with empty permissions list
            - __repr__ returns the namespaced_key
        """
        role = RoleData(external_key=external_key)

        actual_str = str(role)
        actual_repr = repr(role)

        expected_str = f"{expected_name}: "
        self.assertEqual(actual_str, expected_str)
        self.assertEqual(actual_repr, expected_repr)

    def test_role_data_str_with_permissions(self):
        """Test RoleData __str__ method with permissions.

        Expected Result:
            - __str__ returns role name followed by permissions list
        """
        action1 = ActionData(external_key="read")
        action2 = ActionData(external_key="write")
        permission1 = PermissionData(action=action1, effect="allow")
        permission2 = PermissionData(action=action2, effect="deny")
        role = RoleData(external_key="instructor", permissions=[permission1, permission2])

        actual_str = str(role)

        expected_str = "Instructor: Read - allow, Write - deny"
        self.assertEqual(actual_str, expected_str)

    @data(
        ("read", "allow", "Read - allow", "act^read => allow"),
        ("write", "deny", "Write - deny", "act^write => deny"),
        (
            permissions.DELETE_LIBRARY.identifier,
            "allow",
            "Content Libraries > Delete Library - allow",
            "act^content_libraries.delete_library => allow",
        ),
    )
    @unpack
    def test_permission_data_str_and_repr(self, action_key, effect, expected_str, expected_repr):
        """Test PermissionData __str__ and __repr__ methods.

        Expected Result:
            - __str__ returns 'Action Name - effect'
            - __repr__ returns 'namespaced_key => effect'
        """
        action = ActionData(external_key=action_key)
        permission = PermissionData(action=action, effect=effect)

        actual_str = str(permission)
        actual_repr = repr(permission)

        self.assertEqual(actual_str, expected_str)
        self.assertEqual(actual_repr, expected_repr)

    def test_role_assignment_data_str(self):
        """Test RoleAssignmentData __str__ method.

        Expected Result:
            - __str__ returns 'user => role names @ scope'
        """
        user = UserData(external_key="john_doe")
        role1 = RoleData(external_key="instructor")
        role2 = RoleData(external_key=roles.LIBRARY_ADMIN.external_key)
        scope = ContentLibraryData(external_key="lib:DemoX:CSPROB")
        assignment = RoleAssignmentData(subject=user, roles=[role1, role2], scope=scope)

        actual_str = str(assignment)

        expected_str = "john_doe => Instructor, Library Admin @ lib:DemoX:CSPROB"
        self.assertEqual(actual_str, expected_str)

    def test_role_assignment_data_repr(self):
        """Test RoleAssignmentData __repr__ method.

        Expected Result:
            - __repr__ returns 'namespaced_subject => [namespaced_roles] @ namespaced_scope'
        """
        user = UserData(external_key="john_doe")
        role1 = RoleData(external_key="instructor")
        role2 = RoleData(external_key=roles.LIBRARY_ADMIN.external_key)
        scope = ContentLibraryData(external_key="lib:DemoX:CSPROB")
        assignment = RoleAssignmentData(subject=user, roles=[role1, role2], scope=scope)

        actual_repr = repr(assignment)

        expected_repr = "user^john_doe => [role^instructor, role^library_admin] @ lib^lib:DemoX:CSPROB"
        self.assertEqual(actual_repr, expected_repr)


@ddt
class TestContentLibraryData(TestCase):
    """Test the ContentLibraryData class."""

    @patch("openedx_authz.api.data.ContentLibrary")
    def test_get_object_success(self, mock_content_library_model):
        """Test get_object returns ContentLibrary when it exists with valid key.

        Expected Result:
            - Returns the ContentLibrary object when library exists
            - Library key matches exactly (canonical validation passes)
        """
        library_id = "lib:DemoX:CSPROB"
        library_scope = ContentLibraryData(external_key=library_id)
        mock_library_obj = Mock()
        mock_library_obj.library_key = library_scope.library_key
        mock_content_library_model.objects.get_by_key.return_value = mock_library_obj

        result = library_scope.get_object()

        self.assertEqual(result, mock_library_obj)
        mock_content_library_model.objects.get_by_key.assert_called_once_with(library_scope.library_key)

    @patch("openedx_authz.api.data.ContentLibrary")
    def test_get_object_does_not_exist(self, mock_content_library_model):
        """Test get_object returns None when library does not exist.

        Expected Result:
            - Returns None when ContentLibrary.DoesNotExist is raised
        """
        library_id = "lib:DemoX:NonExistent"
        library_scope = ContentLibraryData(external_key=library_id)
        mock_content_library_model.DoesNotExist = Exception
        mock_content_library_model.objects.get_by_key.side_effect = mock_content_library_model.DoesNotExist

        result = library_scope.get_object()

        self.assertIsNone(result)

    @patch("openedx_authz.api.data.ContentLibrary")
    def test_get_object_invalid_key_format(self, mock_content_library_model):
        """Test get_object returns None when library_id has invalid format.

        Expected Result:
            - Returns None when InvalidKeyError is raised during key parsing
        """
        mock_content_library_model.DoesNotExist = Exception
        library_scope = ContentLibraryData(external_key="invalid-library-format")

        result = library_scope.get_object()

        self.assertIsNone(result)
        mock_content_library_model.objects.get_by_key.assert_not_called()

    @patch("openedx_authz.api.data.ContentLibrary")
    def test_get_object_non_canonical_key(self, mock_content_library_model):
        """Test get_object returns None when library key is not canonical.

        This test verifies the canonical key validation: get_by_key is case-insensitive,
        but we require exact match to ensure authorization uses canonical library IDs.

        Expected Result:
            - Returns None when retrieved library's key doesn't match exactly
            - Simulates case where user provides 'lib:demox:csprob' but canonical is 'lib:DemoX:CSPROB'
        """
        library_id = "lib:DemoX:CSPROB"
        library_key = LibraryLocatorV2.from_string(library_id)
        # Convert to lowercase to simulate case-insensitive comparison
        library_scope = ContentLibraryData(external_key=library_id.lower())
        mock_content_library_model.objects.get_by_key.return_value = Mock(library_key=library_key)
        mock_content_library_model.DoesNotExist = Exception

        result = library_scope.get_object()

        self.assertIsNone(result)

    @patch("openedx_authz.api.data.ContentLibrary")
    def test_exists_returns_true_when_library_exists(self, mock_content_library_model):
        """Test exists() returns True when get_object() returns a library.

        Expected Result:
            - exists() returns True when library object is found
        """
        library_id = "lib:DemoX:CSPROB"
        library_scope = ContentLibraryData(external_key=library_id)
        mock_content_library_model.objects.get_by_key.return_value = Mock(library_key=library_scope.library_key)

        result = library_scope.exists()

        self.assertTrue(result)

    @patch("openedx_authz.api.data.ContentLibrary")
    def test_exists_returns_false_when_library_does_not_exist(self, mock_content_library_model):
        """Test exists() returns False when get_object() returns None.

        Expected Result:
            - exists() returns False when library is not found
        """
        library_id = "lib:DemoX:NonExistent"
        library_scope = ContentLibraryData(external_key=library_id)
        mock_content_library_model.DoesNotExist = Exception
        mock_content_library_model.objects.get_by_key.side_effect = mock_content_library_model.DoesNotExist

        result = library_scope.exists()

        self.assertFalse(result)


@ddt
class TestOrgContentLibraryGlobData(TestCase):
    """Tests for the OrgContentLibraryGlobData scope."""

    @data(
        ("lib:DemoX:*", True),
        ("lib:Org-123:*", True),
        ("lib:Org.with.dots:*", True),
        ("lib:Org With Space:*", False),
        ("lib:Org/With/Slash:*", False),
        ("lib:Org\\With\\Backslash:*", False),
        ("lib:Org,With,Comma:*", False),
        ("lib:Org;With;Semicolon:*", False),
        ("lib:Org@WithAt:*", False),
        ("lib:Org#WithHash:*", False),
        ("lib:Org$WithDollar:*", False),
        ("lib:Org&WithAmp:*", False),
        ("lib:Org+WithPlus:*", False),
        ("lib:(Org):*", False),
        ("lib:Org", False),
        ("lib:Org*", False),
        ("other:DemoX:*", False),
        ("lib:DemoX:*:*", False),
    )
    @unpack
    def test_validate_external_key(self, external_key, expected_valid):
        """Validate organization-level library glob external keys."""
        self.assertEqual(OrgContentLibraryGlobData.validate_external_key(external_key), expected_valid)

    @data(
        ("lib:DemoX:*", "DemoX"),
        ("lib:Org-123:*", "Org-123"),
        ("lib:Org.with.dots:*", "Org.with.dots"),
        ("lib:Org:With:Colon:*", "Org:With:Colon"),
        ("lib:DemoX", None),
        ("lib:DemoX:+*", None),
        ("lib:DemoX*", None),
        ("lib:DemoX:**", None),
        ("lib:DemoX:suffix", None),
    )
    @unpack
    def test_get_org(self, external_key, expected_org):
        """Test organization extraction from library glob pattern."""
        self.assertEqual(OrgContentLibraryGlobData.get_org(external_key), expected_org)

    @patch("openedx_authz.api.data.Organization", Organization)
    def test_exists_true_when_org_exists(self):
        """exists() returns True when the org exists."""
        org_name = "DemoX"
        organization = Organization.objects.create(short_name=org_name)
        ContentLibrary.objects.create(org=organization, slug="testlib", title="Test Library")

        result = OrgContentLibraryGlobData(external_key=f"lib:{org_name}:*").exists()

        self.assertTrue(result)

    def test_exists_false_when_org_does_not_exist(self):
        """exists() returns False when the org does not exist."""
        org_name = "DemoX"

        result = OrgContentLibraryGlobData(external_key=f"lib:{org_name}:*").exists()

        self.assertFalse(result)

    def test_exists_false_when_org_cannot_be_parsed(self):
        """exists() returns False when org property is None (invalid pattern)."""
        scope = OrgContentLibraryGlobData(external_key="lib:Invalid+*")

        self.assertIsNone(scope.org)
        self.assertFalse(scope.exists())


@ddt
class TestOrgCourseOverviewGlobData(TestCase):
    """Tests for the OrgCourseOverviewGlobData scope."""

    @data(
        ("course-v1:OpenedX+*", True),
        ("course-v1:My-Org_1+*", True),
        ("course-v1:Org.with.dots+*", True),
        ("course-v1:Org With Space+*", False),
        ("course-v1:Org/With/Slash+*", False),
        ("course-v1:Org\\With\\Backslash+*", False),
        ("course-v1:Org,With,Comma+*", False),
        ("course-v1:Org;With;Semicolon+*", False),
        ("course-v1:Org@WithAt+*", False),
        ("course-v1:Org#WithHash+*", False),
        ("course-v1:Org$WithDollar+*", False),
        ("course-v1:Org&WithAmp+*", False),
        ("course-v1:Org+WithPlus+*", False),
        ("course-v1:(Org)+*", False),
        ("course-v1:Org:With:Plus+*", False),
        ("course-v1:OpenedX", False),
        ("course-v1:OpenedX*", False),
        ("other:OpenedX+*", False),
        ("course-v1:OpenedX**", False),
    )
    @unpack
    def test_validate_external_key(self, external_key, expected_valid):
        """Validate organization-level course glob external keys."""
        self.assertEqual(OrgCourseOverviewGlobData.validate_external_key(external_key), expected_valid)

    @data(
        ("course-v1:OpenedX+*", "OpenedX"),
        ("course-v1:My-Org_1+*", "My-Org_1"),
        ("course-v1:Org.with.dots+*", "Org.with.dots"),
        ("course-v1:Org:With:Plus+*", "Org:With:Plus"),
        ("course-v1:OpenedX", None),
        ("course-v1:OpenedX*", None),
        ("course-v1:OpenedX+**", None),
        ("course-v1:OpenedX+suffix", None),
    )
    @unpack
    def test_get_org(self, external_key, expected_org):
        """Test organization extraction from course glob pattern."""
        self.assertEqual(OrgCourseOverviewGlobData.get_org(external_key), expected_org)

    @patch("openedx_authz.api.data.Organization", Organization)
    def test_exists_true_when_org_exists(self):
        """exists() returns True when the org exists."""
        org_name = "OpenedX"
        Organization.objects.create(short_name=org_name)
        CourseOverview.objects.create(org=org_name, display_name="Test Course")

        result = OrgCourseOverviewGlobData(external_key=f"course-v1:{org_name}+*").exists()

        self.assertTrue(result)

    def test_exists_false_when_org_does_not_exist(self):
        """exists() returns False when the org does not exist."""
        org_name = "OpenedX"

        result = OrgCourseOverviewGlobData(external_key=f"course-v1:{org_name}+*").exists()

        self.assertFalse(result)

    def test_exists_false_when_org_cannot_be_parsed(self):
        """exists() returns False when org property is None (invalid pattern)."""
        scope = OrgCourseOverviewGlobData(external_key="course-v1:Invalid:*")

        self.assertIsNone(scope.org)
        self.assertFalse(scope.exists())
