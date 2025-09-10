from casbin_adapter.adapter import Adapter
from casbin_adapter.models import CasbinRule


class ExtendedAdapter(Adapter):
    def __init__(self):
        super().__init__()

    def load_filtered_policy(self, filter):  # Use py types for filter
        """Load only policy rules that match the filter.

        This filter should come from a more human-readable query format, e.g.:
        {
            "ptype": "p",
            "rule": ["alice", "data1", "read"]
        }
        """
        query_params = {"ptype": filter.get("ptype")}
        for i, v in enumerate(filter.get("rule", [])):
            query_params["v{}".format(i)] = v
        return CasbinRule.objects.using(self.db_alias).filter(**query_params).all()
