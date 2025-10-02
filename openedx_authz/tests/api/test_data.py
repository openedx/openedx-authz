"""Test data for the authorization API."""

from ddt import data, ddt, unpack
from django.test import TestCase

from openedx_authz.api.data import ActionData, ContentLibraryData, RoleData, ScopeData, UserData


@ddt
class TestNamespacedData(TestCase):
    """Test data for the authorization API."""

    @data(
        ("instructor", "role@instructor"),
        ("admin", "role@admin"),
    )
    @unpack
    def test_role_data_namespace(self, input, expected):
        """Test that RoleData correctly namespaces role names.

        Expected Result:
            - If input is 'instructor', expected is 'role@instructor'
            - If input is 'admin', expected is 'role@admin'
        """
        role = RoleData(name=input)
        self.assertEqual(role.role_id, expected)

    @data(
        ("john_doe", "user@john_doe"),
        ("jane_smith", "user@jane_smith"),
    )
    @unpack
    def test_user_data_namespace(self, username, expected):
        """Test that UserData correctly namespaces user IDs.

        Expected Result:
            - If input is 'john_doe', expected is 'user@john_doe'
            - If input is 'jane_smith', expected is 'user@jane_smith'
        """
        user = UserData(username=username)
        self.assertEqual(user.subject_id, expected)

    @data(
        ("read", "act@read"),
        ("write", "act@write"),
    )
    @unpack
    def test_action_data_namespace(self, action_name, expected):
        """Test that ActionData correctly namespaces action IDs.

        Expected Result:
            - If input is 'read', expected is 'act@read'
            - If input is 'write', expected is 'act@write'
        """
        action = ActionData(name=action_name)
        self.assertEqual(action.action_id, expected)

    @data(
        ("lib:DemoX:CSPROB", "lib@lib:demox:csprob"),
    )
    @unpack
    def test_scope_content_lib_data_namespace(self, library_id, expected):
        """Test that ScopeData correctly namespaces scope IDs.

        Expected Result:
            - If input is 'lib:DemoX:CSPROB', expected is 'lib@lib:DemoX:CSPROB'
        """
        scope = ContentLibraryData(library_id=library_id)
        self.assertEqual(scope.scope_id, expected)
