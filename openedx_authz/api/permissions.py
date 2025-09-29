"""Public API for permissions management.

A permission is the authorization granted by a policy. It represents the
allowed actions(s) a subject can perform on an object. In Casbin, permissions
are not explicitly defined, but are inferred from the policy rules.
"""

from typing import Literal

from openedx_authz.api.data import Permission, PolicyIndex
from openedx_authz.engine.enforcer import enforcer

__all__ = ["get_permission_from_policy", "get_all_permissions_in_scope"]


def get_permission_from_policy(policy: list[str]) -> Permission:
    """Convert a Casbin policy list to a Permission object.

    Args:
        policy: A list representing a Casbin policy.

    Returns:
        Permission: The corresponding Permission object or an empty Permission if the policy is invalid.
    """
    if len(policy) < 4:  # Do not count ptype
        return Permission(name="", effect="")

    return Permission(
        name=policy[PolicyIndex.ACT.value], effect=policy[PolicyIndex.EFFECT.value]
    )


def get_all_permissions_in_scope(scope: str) -> list[Permission]:
    """Retrieve all permissions associated with a specific scope.

    Args:
        scope: The scope to filter permissions by.

    Returns:
        list of Permission: A list of Permission objects associated with the given scope.
    """
    actions = enforcer.get_filtered_policy(PolicyIndex.SCOPE.value, scope)
    return [get_permission_from_policy(action) for action in actions]
