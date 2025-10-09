"""Test data for the authorization API."""

from ddt import data, ddt, unpack
from django.test import TestCase

from openedx_authz.api.data import (
    ActionData,
    ContentLibraryData,
    PermissionData,
    RoleAssignmentData,
    RoleData,
    ScopeData,
    ScopeMeta,
    SubjectData,
    UserData,
)


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
            - ScopeData(namespaced_key='sc^generic') creates ScopeData instance
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

        expected_namespaced_key = (
            f"{library.NAMESPACE}{library.SEPARATOR}{external_key}"
        )

        self.assertIsInstance(library, ContentLibraryData)
        self.assertEqual(library.external_key, external_key)
        self.assertEqual(library.namespaced_key, expected_namespaced_key)


@ddt
class TestScopeMetaClass(TestCase):
    """Test the ScopeMeta metaclass functionality."""

    def test_scope_data_registration(self):
        """Test that ScopeData and its subclasses are registered correctly.

        Expected Result:
            - 'sc' namespace maps to ScopeData class
            - 'lib' namespace maps to ContentLibraryData class
        """
        self.assertIn("sc", ScopeData.scope_registry)
        self.assertIs(ScopeData.scope_registry["sc"], ScopeData)
        self.assertIn("lib", ScopeData.scope_registry)
        self.assertIs(ScopeData.scope_registry["lib"], ContentLibraryData)

    @data(
        ("lib^lib:DemoX:CSPROB", ContentLibraryData),
        ("sc^generic_scope", ScopeData),
    )
    @unpack
    def test_dynamic_instantiation_via_namespaced_key(
        self, namespaced_key, expected_class
    ):
        """Test that ScopeData dynamically instantiates the correct subclass.

        Expected Result:
            - ScopeData(namespaced_key='lib^...') returns ContentLibraryData instance
            - ScopeData(namespaced_key='sc^...') returns ScopeData instance
        """
        instance = ScopeData(namespaced_key=namespaced_key)

        self.assertIsInstance(instance, expected_class)
        self.assertEqual(instance.namespaced_key, namespaced_key)

    @data(
        ("lib^lib:DemoX:CSPROB", ContentLibraryData),
        ("sc^generic", ScopeData),
        ("unknown^something", ScopeData),
    )
    @unpack
    def test_get_subclass_by_namespaced_key(self, namespaced_key, expected_class):
        """Test get_subclass_by_namespaced_key returns correct subclass.

        Expected Result:
            - 'lib^...' returns ContentLibraryData
            - 'sc^...' returns ScopeData
            - 'unknown^...' returns ScopeData (fallback)
        """
        subclass = ScopeMeta.get_subclass_by_namespaced_key(namespaced_key)

        self.assertIs(subclass, expected_class)

    @data(
        ("lib:DemoX:CSPROB", ContentLibraryData),
        ("lib:edX:Demo", ContentLibraryData),
        ("sc:generic_scope", ScopeData),
    )
    @unpack
    def test_get_subclass_by_external_key(self, external_key, expected_class):
        """Test get_subclass_by_external_key returns correct subclass.

        Expected Result:
            - 'lib:...' returns ContentLibraryData
            - 'sc:...' returns ScopeData
        """
        subclass = ScopeMeta.get_subclass_by_external_key(external_key)

        self.assertIs(subclass, expected_class)

    @data(
        ("lib:DemoX:CSPROB", True),
        ("lib:edX:Demo", True),
        ("invalid_library_key", False),
        ("lib-DemoX-CSPROB", False),
    )
    @unpack
    def test_content_library_validate_external_key(self, external_key, expected_valid):
        """Test ContentLibraryData.validate_external_key validates library keys.

        Expected Result:
            - Valid library keys (lib:Org:Code) return True
            - Invalid formats return False
        """
        result = ContentLibraryData.validate_external_key(external_key)

        self.assertEqual(result, expected_valid)

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
        scope = ScopeData(external_key="sc:generic_scope")

        expected_namespaced = f"{ScopeData.NAMESPACE}{ScopeData.SEPARATOR}sc:generic_scope"

        self.assertIsInstance(scope, ScopeData)
        self.assertEqual(scope.external_key, "sc:generic_scope")
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
        ("delete_library", "Delete Library", "act^delete_library"),
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
        ("library_admin", "Library Admin", "role^library_admin"),
        ("course_staff", "Course Staff", "role^course_staff"),
    )
    @unpack
    def test_role_data_str_without_permissions(
        self, external_key, expected_name, expected_repr
    ):
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
        ("delete_library", "allow", "Delete Library - allow", "act^delete_library => allow"),
    )
    @unpack
    def test_permission_data_str_and_repr(
        self, action_key, effect, expected_str, expected_repr
    ):
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
        role2 = RoleData(external_key="library_admin")
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
        role2 = RoleData(external_key="library_admin")
        scope = ContentLibraryData(external_key="lib:DemoX:CSPROB")
        assignment = RoleAssignmentData(subject=user, roles=[role1, role2], scope=scope)

        actual_repr = repr(assignment)

        expected_repr = (
            "user^john_doe => [role^instructor, role^library_admin] @ lib^lib:DemoX:CSPROB"
        )
        self.assertEqual(actual_repr, expected_repr)
