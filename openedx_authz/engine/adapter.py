"""
Extended adapter for the casbin model.
"""

from casbin import persist
from casbin.persist import FilteredAdapter
from casbin_adapter.adapter import Adapter
from casbin_adapter.models import CasbinRule


class ExtendedAdapter(Adapter, FilteredAdapter):
    """
    Extended adapter for the casbin model.
    """

    _filtered = True

    def is_filtered(self):
        return self._filtered

    def load_filtered_policy(self, model, filter) -> None:  # pylint: disable=redefined-builtin
        """loads all policy rules from the storage."""
        queryset = CasbinRule.objects.using(self.db_alias)
        filtered_queryset = self.filter_query(queryset, filter)
        for line in filtered_queryset:
            persist.load_policy_line(str(line), model)
        self._filtered = True

    def filter_query(self, queryset, filter):  # pylint: disable=redefined-builtin
        """filters the queryset based on the attributes of the filter."""
        for attr in ("ptype", "v0", "v1", "v2", "v3", "v4", "v5"):
            filter_values = getattr(filter, attr)
            if len(filter_values) > 0:
                filter_kwargs = {f"{attr}__in": filter_values}
                queryset = queryset.filter(**filter_kwargs)
        return queryset.order_by("id")
