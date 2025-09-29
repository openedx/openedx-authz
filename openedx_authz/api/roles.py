"""Public API for roles management.

A role is named group of permissions (actions). Instead of assigning permissions to each
subject, permissions can be assigned to a role, and subjects inherit the role's
permissions.

We'll interact with roles through this API, which will use the enforcer
internally to manage the underlying policies and role assignments.
"""

from openedx_authz.api.data import GroupingPolicyIndex, Permission, PolicyIndex, Role, RoleAssignment, RoleMetadata
from openedx_authz.api.permissions import Permission, get_permission_from_policy
from openedx_authz.engine.enforcer import enforcer

__all__ = [
    "get_permissions_for_roles",
    "get_all_roles_names",
    "get_permissions_for_active_roles_in_scope",
    "get_role_definitions_in_scope",
    "assign_role_to_user_in_scope",
    "batch_assign_role_to_subjects_in_scope",
    "unassign_role_from_subject_in_scope",
    "batch_unassign_role_from_subjects_in_scope",
    "get_roles_for_subject_in_scope",
    "get_role_assignments_in_scope",
    "get_roles_for_subject",
]

# TODO: these are the concerns we still have to address:
# 1. should we dependency inject the enforcer to the API functions?
# For now, we create a global enforcer instance for testing purposes
# 2. Where should we call load_filtered_policy? It makes sense to preload
# it based on the scope for enforcement time? What about these API functions?
# I believe they assume the enforcer is already loaded with the relevant policies
# in this case, ALL the policies, but that might not be the case


def get_permissions_for_roles(
    role_names: list[str] | str,
) -> dict[str, dict[str, list[Permission | str]]]:
    """Get the permissions (actions) for a list of roles.

    Args:
        role_names: A list of role names or a single role name.

    Returns:
        dict[str, list[Permission]]: A dictionary mapping role names to their permissions and scopes.
    """
    permissions_by_role = {}
    if not role_names:
        return permissions_by_role

    if isinstance(role_names, str):
        role_names = [role_names]

    for role_name in role_names:
        policies = enforcer.get_implicit_permissions_for_user(role_name)

        assert (
            permissions_by_role.get(role_name) is not None
        ), "Duplicate role names found"

        permissions_by_role[role_name] = {
            "permissions": [get_permission_from_policy(policy) for policy in policies],
            "scopes": list({perm[2] for perm in policies}),
        }

    return permissions_by_role


def get_permissions_for_active_roles_in_scope(
    scope: str, role_name: str = None
) -> dict[str, dict[str, list[Permission | str]]]:
    """Retrieve all permissions granted by the specified roles within the given scope.

    This function operates on the principle that roles defined in policies are templates
    that become active only when assigned to subjects with specific scopes.

    Role Definition vs Role Assignment:
    - Policy roles define potential permissions with namespace patterns (e.g., 'lib:*')
    - Actual permissions are granted only when roles are assigned to subjects with
      concrete scopes (e.g., 'lib:123')
    - The namespace pattern in the policy ('lib:*') indicates the role is designed
      for resources in that namespace, but doesn't grant blanket access
    - The specific scope at assignment time ('lib:123') determines the exact
      resource the permissions apply to

    Behavior:
    - Returns permissions only for roles that have been assigned to subjects
    - Unassigned roles (those defined in policy but not given to any subject)
      contribute no permissions to the result
    - Scope filtering ensures permissions are returned only for the specified
      resource scope, not for the broader namespace pattern

    Returns:
        dict[str, list[Permission]]: A dictionary mapping the role name to its
        permissions and scopes.
    """
    filtered_policy = enforcer.get_filtered_grouping_policy(
        GroupingPolicyIndex.SCOPE.value, scope
    )

    if role_name:
        filtered_policy = [
            policy
            for policy in filtered_policy
            if policy[GroupingPolicyIndex.ROLE.value] == role_name
        ]

    return get_permissions_for_roles(
        [policy[GroupingPolicyIndex.ROLE.value] for policy in filtered_policy]
    )


def get_role_definitions_in_scope(
    scope: str, include_permissions: bool = False
) -> list[str]:
    """Get all role definitions available in a specific scope.

    See `get_permissions_for_active_roles_in_scope` for explanation of role
    definitions vs assignments.

    Args:
        scope: The scope to filter roles (e.g., 'library:123' or '*' for global).
        include_permissions: Whether to include permissions for each role.

    Returns:
        list[Role]: A list of roles.
    """
    policy_filtered = enforcer.get_filtered_policy(PolicyIndex.SCOPE.value, scope)

    permissions_per_role = {}
    if include_permissions:
        permissions_per_role = get_permissions_for_roles(
            [policy[PolicyIndex.ROLE.value] for policy in policy_filtered]
        )

    return [
        Role(
            name=policy[PolicyIndex.ROLE.value],
            scopes=[policy[PolicyIndex.SCOPE.value]],
            permissions=(
                permissions_per_role.get(policy[PolicyIndex.ROLE.value], {}).get(
                    "permissions", []
                )
                if include_permissions
                else None
            ),
        )
        for policy in policy_filtered
    ]


def get_all_roles_names() -> list[str]:
    """Get all the available roles names in the current environment.

    Returns:
        list[str]: A list of role names.
    """
    return enforcer.get_all_subjects()


def assign_role_to_user_in_scope(subject: str, role_name: str, scope: str) -> None:
    """Assign a role to a subject.

    Args:
        subject: The ID of the subject.
        role: The role to assign.
    """
    assert (
        get_roles_for_subject_in_scope(subject, scope) is not []
    ), "Subject already has a role in the scope"

    enforcer.add_role_for_user_in_domain(subject, role_name, scope)


def batch_assign_role_to_subjects_in_scope(
    subjects: list[str], role_name: str, scope: str
) -> None:
    """Assign a role to a list of subjects.

    Args:
        subjects: A list of subject IDs.
        role: The role to assign.
    """
    for subject in subjects:

        assert (
            get_roles_for_subject_in_scope(subject, scope) is not []
        ), "Subject already has a role in the scope"

        enforcer.add_role_for_user_in_domain(subject, role_name, scope)


def unassign_role_from_subject_in_scope(
    subject: str, role_name: str, scope: str
) -> None:
    """Unassign a role from a subject.

    Args:
        subject: The ID of the subject.
        role: The role to unassign.
        scope: The scope from which to unassign the role.
    """
    enforcer.delete_roles_for_user_in_domain(subject, role_name, scope)


def batch_unassign_role_from_subjects_in_scope(
    subjects: list[str], role_name: str, scope: str
) -> None:
    """Unassign a role from a list of subjects.

    Args:
        subjects: A list of subject IDs.
        role_name: The name of the role.
        scope: The scope from which to unassign the role.
    """
    for subject in subjects:
        enforcer.delete_roles_for_user_in_domain(subject, role_name, scope)


def get_roles_for_subject(
    subject: str, include_permissions: bool = False
) -> list[Role]:
    """Get all the roles for a subject across all scopes.

    Args:
        subject: The ID of the subject namespaced (e.g., 'subject:john_doe').

    Returns:
        list[Role]: A list of role names and all their metadata assigned to the subject.
    """
    roles = []
    for policy in enforcer.get_filtered_grouping_policy(
        GroupingPolicyIndex.SUBJECT.value, subject
    ):
        permissions = []
        if include_permissions:
            permissions = get_permissions_for_roles(
                policy[GroupingPolicyIndex.ROLE.value]
            )[policy[GroupingPolicyIndex.ROLE.value]]["permissions"]

        assert policy[GroupingPolicyIndex.ROLE.value] in {
            role.name for role in roles
        }, "Duplicate role names found"

        roles.append(
            Role(
                name=policy[GroupingPolicyIndex.ROLE.value],
                scopes=[policy[GroupingPolicyIndex.SCOPE.value]],
                permissions=permissions if include_permissions else None,
            )
        )
    return roles


def get_roles_for_subject_in_scope(subject: str, scope: str) -> list[Role]:
    """Get the roles for a subject in a specific scope.

    Args:
        subject: The ID of the subject namespaced (e.g., 'subject:john_doe').
        scope: The scope to filter roles (e.g., 'library:123').

    Returns:
        list[Role]: A list of role names and all their metadata assigned to the subject.
    """
    # TODO: we still need to get the remaining data for the role like email, etc
    roles = []
    for role_name in enforcer.get_roles_for_user_in_domain(subject, scope):
        roles.append(
            Role(
                name=role_name,
                scopes=[scope],
                permissions=get_permissions_for_roles(role_name)[role_name][
                    "permissions"
                ],
            )
        )
    return roles


def get_role_assignments_in_scope(role_name: str, scope: str) -> list[RoleAssignment]:
    """Get the subjects assigned to a specific role in a specific scope.

    Args:
        role_name: The name of the role.
        scope: The scope to filter subjects (e.g., 'library:123' or '*' for global).

    Returns:
        list[RoleAssignment]: A list of subjects assigned to the specified role in the specified scope.
    """
    subjects = []
    for subject in enforcer.get_users_for_role_in_domain(role_name, scope):
        if subject.startswith("role:"):
            # Skip roles that are also subjects
            continue
        subjects.append(
            RoleAssignment(
                subject=subject,
                role=Role(
                    name=role_name,
                    scopes=[scope],
                    permissions=get_permissions_for_roles(role_name)[role_name][
                        "permissions"
                    ],
                ),
            )
        )
    return subjects
