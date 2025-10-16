"""Public API for permissions management.

A permission is the authorization granted by a policy. It represents the
allowed actions(s) a subject can perform on an object. In Casbin, permissions
are not explicitly defined, but are inferred from the policy rules.
"""

from openedx_authz.api.data import ActionData, PermissionData, PolicyIndex, ScopeData, SubjectData
from openedx_authz.engine.enforcer import AuthzEnforcer

__all__ = [
    "get_permission_from_policy",
    "get_all_permissions_in_scope",
    "is_subject_allowed",
]


def get_permission_from_policy(policy: list[str]) -> PermissionData:
    """Convert a Casbin policy list to a PermissionData object.

    Args:
        policy: A list representing a Casbin policy.

    Returns:
        PermissionData: The corresponding PermissionData object or an empty PermissionData if the policy is invalid.
    """
    if len(policy) < 4:  # Do not count ptype
        raise ValueError("Invalid policy format. Expected at least 4 elements.")

    return PermissionData(
        action=ActionData(namespaced_key=policy[PolicyIndex.ACT.value]),
        effect=policy[PolicyIndex.EFFECT.value],
    )


def get_all_permissions_in_scope(scope: ScopeData) -> list[PermissionData]:
    """Retrieve all permissions associated with a specific scope.

    Args:
        scope: The scope to filter permissions by.

    Returns:
        list of PermissionData: A list of PermissionData objects associated with the given scope.
    """
    enforcer = AuthzEnforcer.get_enforcer()
    actions = enforcer.get_filtered_policy(
        PolicyIndex.SCOPE.value, scope.namespaced_key
    )
    return [get_permission_from_policy(action) for action in actions]


def is_subject_allowed(
    subject: SubjectData,
    action: ActionData,
    scope: ScopeData,
) -> bool:
    """Check if a subject has a specific permission in a given scope.

    Args:
        subject: The subject to check (e.g., user or service).
        action: The action to check (e.g., 'view_course').
        scope: The scope in which to check the permission (e.g., 'course-v1:edX+DemoX+2021_T1').

    Returns:
        bool: True if the subject has the specified permission in the scope, False otherwise.
    """
    enforcer = AuthzEnforcer.get_enforcer()
    enforcer.load_policy()
    return enforcer.enforce(
        subject.namespaced_key, action.namespaced_key, scope.namespaced_key
    )
