"""Unit tests for the role catalog filter backends in openedx_authz.rest_api.v1.admin_console.filters."""

from types import SimpleNamespace

from ddt import data, ddt, unpack
from django.test import TestCase
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from openedx_authz.api.data import DefinitionKind
from openedx_authz.rest_api.v1.admin_console.filters import RoleOrderingFilter, RoleSearchFilter
from openedx_authz.rest_api.v1.serializers import ListRolesQuerySerializer

ROLES = [
    {"role": "library_user", "display_name": "Library User", "definition_kind": DefinitionKind.STATIC.value},
    {"role": "custom_role", "display_name": "Grader", "definition_kind": DefinitionKind.USER_DEFINED.value},
    {"role": "library_author", "display_name": "Library Author", "definition_kind": DefinitionKind.STATIC.value},
]


def _request_and_view(query_params: dict) -> tuple[Request, SimpleNamespace]:
    """Build a request and a view carrying the parameters as ``RoleListView`` validates them."""
    request = Request(APIRequestFactory().get("/", {"scope_types": "lib", **query_params}))
    serializer = ListRolesQuerySerializer(data=request.query_params)
    serializer.is_valid(raise_exception=True)
    return request, SimpleNamespace(validated_query_params=serializer.validated_data)


@ddt
class TestRoleSearchFilter(TestCase):
    """Tests for RoleSearchFilter."""

    @data(
        ({}, ["library_user", "custom_role", "library_author"]),
        ({"search": "LIBRARY"}, ["library_user", "library_author"]),
        ({"definition_kind": "user_defined"}, ["custom_role"]),
        ({"search": "library", "definition_kind": "user_defined"}, []),
        ({"definition_kind": ""}, ["library_user", "custom_role", "library_author"]),
        # Regression: the validated search is stripped, so surrounding spaces still match
        ({"search": "  author "}, ["library_author"]),
    )
    @unpack
    def test_filters_by_query_params(self, query_params: dict, expected: list[str]):
        """The search and definition_kind query parameters filter the roles."""
        request, view = _request_and_view(query_params)

        result = RoleSearchFilter().filter_queryset(request, ROLES, view=view)

        self.assertEqual([role["role"] for role in result], expected)


@ddt
class TestRoleOrderingFilter(TestCase):
    """Tests for RoleOrderingFilter."""

    @data(
        ({}, ["library_author", "library_user", "custom_role"]),
        ({"sort_by": "", "order": ""}, ["library_author", "library_user", "custom_role"]),
        ({"order": "desc"}, ["custom_role", "library_user", "library_author"]),
        ({"sort_by": "display_name", "order": "asc"}, ["library_author", "library_user", "custom_role"]),
    )
    @unpack
    def test_sorts_by_query_params(self, query_params: dict, expected: list[str]):
        """Roles are sorted by sort_by and order, defaulting to display name ascending."""
        roles = [{**role, "display_name": name} for role, name in zip(ROLES, ["B", "C", "A"])]

        request, view = _request_and_view(query_params)

        result = RoleOrderingFilter().filter_queryset(request, roles, view=view)

        self.assertEqual([role["role"] for role in result], expected)
