"""Custom DRF filter backends for the Open edX AuthZ REST API."""

from rest_framework.filters import BaseFilterBackend

from openedx_authz.rest_api.data import AssignmentSortField, SortField, SortOrder
from openedx_authz.rest_api.utils import filter_users, sort_assignments, sort_users


class TeamMemberSearchFilter(BaseFilterBackend):
    """Filter team members by a search term."""

    def filter_queryset(self, request, queryset, view):
        search = request.query_params.get("search")
        return filter_users(users=queryset, search=search, roles=None)


class TeamMemberOrderingFilter(BaseFilterBackend):
    """Sort team members by a given field and order."""

    def filter_queryset(self, request, queryset, view):
        sort_by = request.query_params.get("sort_by", SortField.USERNAME)
        order = request.query_params.get("order", SortOrder.ASC)
        return sort_users(users=queryset, sort_by=sort_by, order=order)


class TeamMemberAssignmentsOrderingFilter(BaseFilterBackend):
    """Sort team member assignments by a given field and order."""

    def filter_queryset(self, request, queryset, view):
        sort_by = request.query_params.get("sort_by", AssignmentSortField.ROLE)
        order = request.query_params.get("order", SortOrder.ASC)
        return sort_assignments(assignments=queryset, sort_by=sort_by, order=order)
