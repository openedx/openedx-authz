"""Decorators for the authorization public API."""
from functools import wraps

from openedx_authz.api.data import ScopeData
from openedx_authz.engine.enforcer import enforcer
from openedx_authz.engine.filter import Filter


def manage_policy_lifecycle(filter_on: str = ""):
    """Decorator to manage policy lifecycle around API calls.

    This decorator ensures proper policy loading and clearing around API function calls.
    It loads relevant policies before execution and clears them afterward to prevent
    stale policy issues in long-running processes.

    Can be used in two ways:
        @manage_policy_lifecycle()                   -> Loads full policy
        @manage_policy_lifecycle(filter_on="scope")  -> Loads filtered policy by scope

    Args:
        filter_on (str): The type of data class to filter on (e.g., "scope").
            If empty, loads full policy.

    Returns:
        callable: The decorated function or decorator.

    Examples:
        # Without filtering (loads all policies):
        @manage_policy_lifecycle()
        def get_all_roles():
            return enforcer.get_all_roles()

        # With scope filtering (loads only relevant policies):
        @manage_policy_lifecycle(filter_on="scope")
        def get_roles_in_scope(scope: ScopeData):
            return enforcer.get_filtered_roles(scope.namespaced_key)
    """
    FILTER_DATA_CLASSES = {
        "scope": ScopeData,
    }

    def build_filter_from_args(args) -> Filter:
        """Build a Filter object from function arguments based on the filter_on parameter.

        Args:
            args (tuple): Positional arguments passed to the decorated function.

        Returns:
            Filter: A Filter object populated with relevant filter values.
        """
        filter_obj = Filter()
        if not filter_on or filter_on not in FILTER_DATA_CLASSES:
            return filter_obj

        for arg in args:
            if isinstance(arg, FILTER_DATA_CLASSES[filter_on]):
                filter_value = getattr(filter_obj, f"v{arg.POLICY_POSITION}")
                filter_value.append(arg.policy_template)  # Used to load p type policies as well. E.g., lib^*
                filter_value.append(arg.namespaced_key)  # E.g., lib^lib:DemoX:CSPROB

        return filter_obj

    def decorator(f):
        """Inner decorator that wraps the function with policy lifecycle management."""
        @wraps(f)
        def wrapper(*args, **kwargs):
            """Wrapper that handles policy loading, execution, and cleanup."""
            filter_obj = build_filter_from_args(args)

            if any([filter_obj.ptype, filter_obj.v0, filter_obj.v1, filter_obj.v2]):
                enforcer.load_filtered_policy(filter_obj)
            else:
                enforcer.load_policy()

            try:
                return f(*args, **kwargs)
            finally:
                enforcer.clear_policy()

        return wrapper

    return decorator
