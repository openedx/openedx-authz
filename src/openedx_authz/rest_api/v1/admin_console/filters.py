"""Custom DRF filter backends for the Open edX AuthZ REST API."""

from rest_framework.filters import BaseFilterBackend

from openedx_authz.rest_api.data import (
    AssignmentSortField,
    SearchField,
    SortField,
    SortOrder,
    UserAssignmentSortField,
)
from openedx_authz.rest_api.utils import (
    filter_roles,
    filter_users,
    sort_assignments,
    sort_roles,
    sort_user_assignments,
    sort_users,
)


class TeamMemberSearchFilter(BaseFilterBackend):
    """Filter team members by a search term."""

    def filter_queryset(self, request, queryset, view):
        search = request.query_params.get("search")
        return filter_users(users=queryset, search=search, roles=None)


class TeamMemberOrderingFilter(BaseFilterBackend):
    """Sort team members by a given field and order.

    An empty ``sort_by`` or ``order`` (e.g. ``?sort_by=``) falls back to the default, as the query
    serializer does. Passing the empty string on would make the sort raise ``ValueError`` (a 500).
    The other ordering backends below follow the same rule.
    """

    def filter_queryset(self, request, queryset, view):
        sort_by = request.query_params.get("sort_by") or SortField.USERNAME
        order = request.query_params.get("order") or SortOrder.ASC
        return sort_users(users=queryset, sort_by=sort_by, order=order)


class TeamMemberAssignmentsOrderingFilter(BaseFilterBackend):
    """Sort team member assignments by a given field and order."""

    def filter_queryset(self, request, queryset, view):
        sort_by = request.query_params.get("sort_by") or AssignmentSortField.ROLE
        order = request.query_params.get("order") or SortOrder.ASC
        return sort_assignments(assignments=queryset, sort_by=sort_by, order=order)


class UserAssignmentsSearchFilter(BaseFilterBackend):
    """Filter user assignments by a search term over full_name, username, and email."""

    def filter_queryset(self, request, queryset, view):
        search = request.query_params.get("search")
        if not search:
            return queryset
        search = search.lower()
        return [
            item
            for item in queryset
            if any(search in (item.get(field) or "").lower() for field in SearchField.values())
        ]


class UserAssignmentsOrderingFilter(BaseFilterBackend):
    """Sort user assignments by a given field and order."""

    def filter_queryset(self, request, queryset, view):
        sort_by = request.query_params.get("sort_by") or UserAssignmentSortField.FULL_NAME
        order = request.query_params.get("order") or SortOrder.ASC
        return sort_user_assignments(assignments=queryset, sort_by=sort_by, order=order)


class RoleSearchFilter(BaseFilterBackend):
    """Filter role catalog entries by display name and definition kind.

    Reads ``view.validated_query_params``, the output of ``ListRolesQuerySerializer``, instead of the
    raw query string, so the values are already stripped, lowercased and defaulted. Reading the raw
    ``search`` would miss matches for values with surrounding spaces.
    """

    def filter_queryset(self, request, queryset, view):
        params = view.validated_query_params
        return filter_roles(roles=queryset, search=params["search"], definition_kind=params["definition_kind"])


class RoleOrderingFilter(BaseFilterBackend):
    """Sort role catalog entries by a given field and order.

    Reads ``view.validated_query_params``, like :class:`RoleSearchFilter`, so empty values already
    carry the serializer defaults and only supported values reach :func:`sort_roles`.
    """

    def filter_queryset(self, request, queryset, view):
        params = view.validated_query_params
        return sort_roles(roles=queryset, sort_by=params["sort_by"], order=params["order"])
