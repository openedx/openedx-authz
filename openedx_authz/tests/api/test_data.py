"""Test data for the authorization API."""

from ddt import data, ddt, unpack
from django.test import TestCase

from openedx_authz.api.data import ActionData, ContentLibraryData, RoleData, ScopeData, SubjectData, UserData


@ddt
class TestNamespacedData(TestCase):
    """Test data for the authorization API."""

    @data(
        ("instructor", "role@instructor"),
        ("admin", "role@admin"),
    )
    @unpack
    def test_role_data_namespace(self, external_key, expected):
        """Test that RoleData correctly namespaces role names.

        Expected Result:
            - If input is 'instructor', expected is 'role@instructor'
            - If input is 'admin', expected is 'role@admin'
        """
        role = RoleData(external_key=external_key)
        self.assertEqual(role.namespaced_key, expected)

    @data(
        ("john_doe", "user@john_doe"),
        ("jane_smith", "user@jane_smith"),
    )
    @unpack
    def test_user_data_namespace(self, external_key, expected):
        """Test that UserData correctly namespaces user IDs.

        Expected Result:
            - If input is 'john_doe', expected is 'user@john_doe'
            - If input is 'jane_smith', expected is 'user@jane_smith'
        """
        user = UserData(external_key=external_key)
        self.assertEqual(user.namespaced_key, expected)

    @data(
        ("read", "act@read"),
        ("write", "act@write"),
    )
    @unpack
    def test_action_data_namespace(self, external_key, expected):
        """Test that ActionData correctly namespaces action IDs.

        Expected Result:
            - If input is 'read', expected is 'act@read'
            - If input is 'write', expected is 'act@write'
        """
        action = ActionData(external_key=external_key)
        self.assertEqual(action.namespaced_key, expected)

    @data(
        ("lib:DemoX:CSPROB", "lib@lib:DemoX:CSPROB"),
    )
    @unpack
    def test_scope_content_lib_data_namespace(self, external_key, expected):
        """Test that ContentLibraryData correctly namespaces library IDs.

        Expected Result:
            - If input is 'lib:DemoX:CSPROB', expected is 'lib@lib:DemoX:CSPROB'
        """
        scope = ContentLibraryData(external_key=external_key)
        self.assertEqual(scope.namespaced_key, expected)


@ddt
class TestPolymorphismLowLevelAPIs(TestCase):
    """Test polymorphic factory pattern for SubjectData and ScopeData."""

    @data(
        ("user@john_doe", "john_doe"),
        ("user@jane_smith", "jane_smith"),
    )
    @unpack
    def test_user_data_with_namespaced_key(self, namespaced_key, expected_external_key):
        """Test that UserData can be instantiated with namespaced_key.

        Expected Result:
            - UserData(namespaced_key='user@john_doe') creates UserData instance
        """
        user = UserData(namespaced_key=namespaced_key)
        self.assertIsInstance(user, UserData)
        self.assertEqual(user.namespaced_key, namespaced_key)
        self.assertEqual(user.external_key, expected_external_key)

    def test_subject_data_direct_instantiation_with_namespaced_key(self):
        """Test that SubjectData can be instantiated with namespaced_key.

        Expected Result:
            - SubjectData(namespaced_key='sub@generic') creates SubjectData instance
        """
        subject = SubjectData(namespaced_key="sub@generic")
        self.assertIsInstance(subject, SubjectData)
        self.assertEqual(subject.namespaced_key, "sub@generic")
        self.assertEqual(subject.external_key, "generic")

    @data(
        ("lib@math_101", "math_101"),
        ("lib@science_201", "science_201"),
    )
    @unpack
    def test_content_library_data_with_namespaced_key(self, namespaced_key, expected_external_key):
        """Test that ContentLibraryData can be instantiated with namespaced_key.

        Expected Result:
            - ContentLibraryData(namespaced_key='lib@math_101') creates ContentLibraryData instance
        """
        library = ContentLibraryData(namespaced_key=namespaced_key)
        self.assertIsInstance(library, ContentLibraryData)
        self.assertEqual(library.namespaced_key, namespaced_key)
        self.assertEqual(library.external_key, expected_external_key)

    def test_scope_data_direct_instantiation_with_namespaced_key(self):
        """Test that ScopeData can be instantiated with namespaced_key.

        Expected Result:
            - ScopeData(namespaced_key='sc@generic') creates ScopeData instance
        """
        scope = ScopeData(namespaced_key="sc@generic")
        self.assertIsInstance(scope, ScopeData)
        self.assertEqual(scope.namespaced_key, "sc@generic")
        self.assertEqual(scope.external_key, "generic")

    def test_user_data_direct_instantiation(self):
        """Test that UserData can be instantiated directly.

        Expected Result:
            - UserData(external_key='alice') creates UserData instance
        """
        user = UserData(external_key="alice")
        self.assertIsInstance(user, UserData)
        self.assertEqual(user.namespaced_key, "user@alice")
        self.assertEqual(user.external_key, "alice")

    def test_content_library_direct_instantiation(self):
        """Test that ContentLibraryData can be instantiated directly.

        Expected Result:
            - ContentLibraryData(external_key='lib:Demo:CS') creates ContentLibraryData instance
        """
        library = ContentLibraryData(external_key="lib:demo:cs")
        self.assertIsInstance(library, ContentLibraryData)
        self.assertEqual(library.namespaced_key, "lib@lib:demo:cs")
        self.assertEqual(library.external_key, "lib:demo:cs")

    @data(
        ("lib:math_101", "lib@lib:math_101"),
        ("lib:DemoX:CSPROB", "lib@lib:DemoX:CSPROB"),
    )
    @unpack
    def test_content_library_data_with_external_key(self, external_key, expected_namespaced_key):
        """Test that ContentLibraryData with external_key generates correct namespaced_key.

        Expected Result:
            - ContentLibraryData(external_key='lib:math_101') creates ContentLibraryData instance
            - namespaced_key is 'lib@lib:math_101'
        """
        library = ContentLibraryData(external_key=external_key)
        self.assertIsInstance(library, ContentLibraryData)
        self.assertEqual(library.external_key, external_key)
        self.assertEqual(library.namespaced_key, expected_namespaced_key)
