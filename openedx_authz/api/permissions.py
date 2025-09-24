"""Public API for permissions management.

A permission is the authorization granted by a policy. It represents the
allowed actions(s) a subject can perform on an object. In Casbin, permissions
are not explicitly defined, but are inferred from the policy rules.
"""


def has_permission(user: str, resource: str, action: str, scope: str = None) -> bool:
    """Check if a user has a specific permission.

    Args:
        user: The user to check.
        resource: The resource to check.
        action: The action to check.
        scope: The scope to check (optional).
    """
