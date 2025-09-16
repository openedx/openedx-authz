"""
Extended Casbin Adapter with Filtering Support.

This module provides an enhanced adapter implementation for Casbin that extends
the base Django adapter with filtering capabilities. The ExtendedAdapter allows
for efficient loading of policy rules from the database with support for
filtering based on policy attributes.

The adapter combines functionality from both the base Adapter (for Django ORM
integration) and FilteredAdapter (for selective policy loading) to provide
optimized policy management for authorization systems.
"""

from casbin import persist
from casbin.model import Model
from casbin.persist import FilteredAdapter
from casbin_adapter.adapter import Adapter
from casbin_adapter.models import CasbinRule
from django.db.models import QuerySet

from openedx_authz.engine.filter import Filter


class ExtendedAdapter(Adapter, FilteredAdapter):
    """
    Extended Casbin adapter with filtering capabilities.

    This adapter extends the base Django ORM Casbin adapter to support filtered
    policy loading, allowing for more efficient policy management by loading
    only relevant policy rules based on specified filter criteria.

    Inherits from:
        Adapter: Base Django adapter for Casbin policy persistence.
        FilteredAdapter: Interface for filtered policy loading.

    Attributes:
        _filtered (bool): Flag indicating whether the adapter supports filtering.
    """

    _filtered = True

    def is_filtered(self) -> bool:
        """
        Check if the adapter supports filtering.

        Returns:
            bool: True if the adapter supports filtered policy loading, False otherwise.
        """
        return self._filtered

    def load_filtered_policy(self, model: Model, filter: Filter) -> None:  # pylint: disable=redefined-builtin
        """
        Load policy rules from storage with filtering applied.

        This method loads policy rules from the database and applies the specified
        filter to load only relevant rules. The filtered rules are then loaded
        into the provided Casbin model.

        Args:
            model (Model): The Casbin model to load policy rules into.
            filter (Filter): Filter object containing criteria for policy selection.
                   Should have attributes like ptype, v0, v1, etc. with lists
                   of values to filter by.
        """
        queryset = CasbinRule.objects.using(self.db_alias)
        filtered_queryset = self.filter_query(queryset, filter)
        for line in filtered_queryset:
            persist.load_policy_line(str(line), model)
        self._filtered = True

    def filter_query(self, queryset: QuerySet, filter: Filter) -> QuerySet:  # pylint: disable=redefined-builtin
        """
        Apply filter criteria to the policy queryset.

        This method takes a Django queryset of CasbinRule objects and applies
        filtering based on the provided filter object's attributes. It supports
        filtering by policy type (ptype) and policy values (v0-v5).

        Args:
            queryset (QuerySet): Django queryset of CasbinRule objects to filter.
            filter (Filter): Filter object with attributes (ptype, v0, v1, v2, v3, v4, v5)
                   containing lists of values to filter by. Empty lists are ignored.

        Returns:
            QuerySet: Filtered and ordered queryset of CasbinRule objects.
        """
        for attr in ("ptype", "v0", "v1", "v2", "v3", "v4", "v5"):
            filter_values = getattr(filter, attr)
            if len(filter_values) > 0:
                filter_kwargs = {f"{attr}__in": filter_values}
                queryset = queryset.filter(**filter_kwargs)
        return queryset.order_by("id")
