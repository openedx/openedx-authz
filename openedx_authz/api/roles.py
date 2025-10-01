"""Public API for roles management.

A role is named group of permissions (actions). Instead of assigning permissions to each
subject, permissions can be assigned to a role, and subjects inherit the role's
permissions.

We'll interact with roles through this API, which will use the enforcer
internally to manage the underlying policies and role assignments.
"""

from collections import defaultdict

from openedx_authz.api.data import (
    GroupingPolicyIndex,
    PermissionData,
    PolicyIndex,
    RoleAssignmentData,
    RoleData,
    RoleMetadataData,
    ScopeData,
    SubjectData,
    UserData,
)
from openedx_authz.api.permissions import get_permission_from_policy
from openedx_authz.engine.enforcer import enforcer

__all__ = [
    "get_permissions_for_roles",
    "get_all_roles_names",
    "get_permissions_for_active_roles_in_scope",
    "get_role_definitions_in_scope",
    "assign_role_to_subject_in_scope",
    "batch_assign_role_to_subjects_in_scope",
    "unassign_role_from_subject_in_scope",
    "batch_unassign_role_from_subjects_in_scope",
    "get_subject_role_assignments_in_scope",
    "get_subjects_role_assignments_for_role_in_scope",
    "get_subject_role_assignments",
]

# TODO: these are the concerns we still have to address:
# 1. should we dependency inject the enforcer to the API functions?
# For now, we create a global enforcer instance for testing purposes
# 2. Where should we call load_filtered_policy? It makes sense to preload
# it based on the scope for enforcement time? What about these API functions?
# I believe they assume the enforcer is already loaded with the relevant policies
# in this case, ALL the policies, but that might not be the case


def get_permissions_for_roles(
    roles: list[RoleData] | RoleData,
) -> dict[str, dict[str, list[PermissionData | str]]]:
    """Get the permissions (actions) for a list of roles.

    Args:
        role_names: A list of role names or a single role name.

    Returns:
        dict[str, list[PermissionData]]: A dictionary mapping role names to their permissions and scopes.
    """
    permissions_by_role = {}
    if not roles:
        return permissions_by_role

    if isinstance(roles, RoleData):
        roles = [roles]

    for role in roles:
        policies = enforcer.get_implicit_permissions_for_user(role.role_id)

        permissions_by_role[role.name] = {  # Index by role name for easy lookup
            "permissions": [get_permission_from_policy(policy) for policy in policies],
        }

    return permissions_by_role


def get_permissions_for_active_roles_in_scope(
    scope: ScopeData, role: RoleData | None = None
) -> dict[str, dict[str, list[PermissionData | str]]]:
    """Retrieve all permissions granted by the specified roles within the given scope.

    This function operates on the principle that roles defined in policies are templates
    that become active only when assigned to subjects with specific scopes.

    Role Definition vs Role Assignment:
    - Policy roles define potential permissions with namespace patterns (e.g., 'lib@*')
    - Actual permissions are granted only when roles are assigned to subjects with
      concrete scopes (e.g., 'lib@123')
    - The namespace pattern in the policy ('lib@*') indicates the role is designed
      for resources in that namespace, but doesn't grant blanket access
    - The specific scope at assignment time ('lib@123') determines the exact
      resource the permissions apply to

    Behavior:
    - Returns permissions only for roles that have been assigned to subjects
    - Unassigned roles (those defined in policy but not given to any subject)
      contribute no permissions to the result
    - Scope filtering ensures permissions are returned only for the specified
      resource scope, not for the broader namespace pattern

    Returns:
        dict[str, list[PermissionData]]: A dictionary mapping the role name to its
        permissions and scopes.
    """
    filtered_policy = enforcer.get_filtered_grouping_policy(
        GroupingPolicyIndex.SCOPE.value, scope.scope_id
    )

    if role:
        filtered_policy = [
            policy
            for policy in filtered_policy
            if policy[GroupingPolicyIndex.ROLE.value] == role.role_id
        ]

    return get_permissions_for_roles(
        [
            RoleData(role_id=policy[GroupingPolicyIndex.ROLE.value])
            for policy in filtered_policy
        ]
    )


def get_role_definitions_in_scope(scope: ScopeData) -> list[RoleData]:
    """Get all role definitions available in a specific scope.

    See `get_permissions_for_active_roles_in_scope` for explanation of role
    definitions vs assignments.

    Args:
        scope: The scope to filter roles (e.g., 'lib@*' or '*' for global).

    Returns:
        list[Role]: A list of roles.
    """
    policy_filtered = enforcer.get_filtered_policy(
        PolicyIndex.SCOPE.value, scope.scope_id
    )

    permissions_per_role = defaultdict(
        lambda: {
            "permissions": [],
            "scopes": [],
        }
    )
    for policy in policy_filtered:
        permissions_per_role[policy[PolicyIndex.ROLE.value]]["scopes"].append(
            ScopeData(scope_id=policy[PolicyIndex.SCOPE.value])
        )  # TODO: I don't think this actually gets used anywhere
        permissions_per_role[policy[PolicyIndex.ROLE.value]]["permissions"].append(
            get_permission_from_policy(policy)
        )

    return [
        RoleData(
            role_id=role,
            permissions=permissions_per_role[role]["permissions"],
        )
        for role in permissions_per_role.keys()
    ]


def get_all_roles_names() -> list[str]:
    """Get all the available roles names in the current environment.

    Returns:
        list[str]: A list of role names.
    """
    return enforcer.get_all_subjects()


def assign_role_to_subject_in_scope(
    subject: SubjectData, role: RoleData, scope: ScopeData
) -> None:
    """Assign a role to a subject.

    Args:
        subject: The ID of the subject.
        role: The role to assign.
    """
    assert (
        get_subject_role_assignments_in_scope(subject, scope) == []
    ), "Subject already has a role in the scope"

    # TODO: we need to make some uppercase/lowercase decisions in the lookups
    # for now, we assume the caller has done the right thing
    # and passed in the correctly namespaced IDs
    enforcer.add_role_for_user_in_domain(
        subject.subject_id.lower(), role.role_id.lower(), scope.scope_id.lower()
    )


def batch_assign_role_to_subjects_in_scope(
    subjects: list[SubjectData], role: RoleData, scope: ScopeData
) -> None:
    """Assign a role to a list of subjects.

    Args:
        subjects: A list of subject IDs.
        role: The role to assign.
    """
    for subject in subjects:
        assign_role_to_subject_in_scope(subject, role, scope)


def unassign_role_from_subject_in_scope(
    subject: SubjectData, role: RoleData, scope: ScopeData
) -> None:
    """Unassign a role from a subject.

    Args:
        subject: The ID of the subject.
        role: The role to unassign.
        scope: The scope from which to unassign the role.
    """
    enforcer.delete_roles_for_user_in_domain(
        subject.subject_id, role.role_id, scope.scope_id
    )


def batch_unassign_role_from_subjects_in_scope(
    subjects: list[SubjectData], role: RoleData, scope: ScopeData
) -> None:
    """Unassign a role from a list of subjects.

    Args:
        subjects: A list of subject IDs.
        role_name: The name of the role.
        scope: The scope from which to unassign the role.
    """
    for subject in subjects:
        unassign_role_from_subject_in_scope(subject, role, scope)


def get_subject_role_assignments(subject: SubjectData) -> list[RoleAssignmentData]:
    """Get all the roles for a subject across all scopes.

    Args:
        subject: The ID of the subject namespaced (e.g., 'subject:john_doe').

    Returns:
        list[Role]: A list of role names and all their metadata assigned to the subject.
    """
    role_assignments = []
    for policy in enforcer.get_filtered_grouping_policy(
        GroupingPolicyIndex.SUBJECT.value, subject.subject_id
    ):
        role = RoleData(role_id=policy[GroupingPolicyIndex.ROLE.value])
        role.permissions = get_permissions_for_roles(role)[role.name][  # Index by role name for readability
            "permissions"
        ]

        role_assignments.append(
            RoleAssignmentData(
                subject=subject,
                role=role,
                scope=ScopeData(scope_id=policy[GroupingPolicyIndex.SCOPE.value]),
            )
        )
    return role_assignments


def get_subject_role_assignments_in_scope(
    subject: SubjectData, scope: ScopeData
) -> list[RoleAssignmentData]:
    """Get the roles for a subject in a specific scope.

    Args:
        subject: The ID of the subject namespaced (e.g., 'subject:john_doe').
        scope: The scope to filter roles (e.g., 'library:123').

    Returns:
        list[RoleAssignment]: A list of role assignments for the subject in the scope.
    """
    # TODO: we still need to get the remaining data for the role like email, etc
    role_assignments = []
    for role_id in enforcer.get_roles_for_user_in_domain(
        subject.subject_id, scope.scope_id
    ):
        role_assignments.append(
            RoleAssignmentData(
                subject=subject,
                role=RoleData(
                    role_id=role_id,
                    permissions=get_permissions_for_roles(RoleData(name=role_id))[
                        role_id
                    ]["permissions"],
                ),
                scope=scope,
            )
        )
    return role_assignments


def get_subjects_role_assignments_for_role_in_scope(
    role: RoleData, scope: ScopeData
) -> list[RoleAssignmentData]:
    """Get the subjects assigned to a specific role in a specific scope.

    Args:
        role: The role data.
        scope: The scope to filter subjects (e.g., 'library:123' or '*' for global).

    Returns:
        list[RoleAssignment]: A list of subjects assigned to the specified role in the specified scope.
    """
    role_assignments = []
    for subject in enforcer.get_users_for_role_in_domain(role.role_id, scope.scope_id):
        if subject.startswith(RoleData.NAMESPACE):
            # Skip roles that are also subjects
            continue
        role_assignments.append(
            RoleAssignmentData(
                subject=SubjectData(subject_id=subject),
                role=RoleData(
                    name=role.name,
                    permissions=get_permissions_for_roles(role)[role.name][
                        "permissions"
                    ],
                ),
                scope=scope,
            )
        )
    return role_assignments
