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
    ScopeData,
    SubjectData,
)
from openedx_authz.api.permissions import get_permission_from_policy
from openedx_authz.engine.enforcer import AuthzEnforcer

__all__ = [
    "get_permissions_for_single_role",
    "get_permissions_for_roles",
    "get_all_roles_names",
    "get_all_roles_in_scope",
    "get_permissions_for_active_roles_in_scope",
    "get_role_definitions_in_scope",
    "assign_role_to_subject_in_scope",
    "batch_assign_role_to_subjects_in_scope",
    "unassign_role_from_subject_in_scope",
    "batch_unassign_role_from_subjects_in_scope",
    "get_subject_role_assignments_in_scope",
    "get_subject_role_assignments_for_role_in_scope",
    "get_all_subject_role_assignments_in_scope",
    "get_subject_role_assignments",
]

# TODO: these are the concerns we still have to address:
# 1. should we dependency inject the enforcer to the API functions?
# For now, we create a global enforcer instance for testing purposes
# 2. Where should we call load_filtered_policy? It makes sense to preload
# it based on the scope for enforcement time? What about these API functions?
# I believe they assume the enforcer is already loaded with the relevant policies
# in this case, ALL the policies, but that might not be the case


def get_permissions_for_single_role(
    role: RoleData,
) -> list[PermissionData]:
    """Get the permissions (actions) for a single role.

    Args:
        role: A RoleData object representing the role.

    Returns:
        list[PermissionData]: A list of PermissionData objects associated with the given role.
    """
    enforcer = AuthzEnforcer.get_enforcer()
    policies = enforcer.get_implicit_permissions_for_user(role.namespaced_key)
    return [get_permission_from_policy(policy) for policy in policies]


def get_permissions_for_roles(
    roles: list[RoleData],
) -> dict[str, dict[str, list[PermissionData | str]]]:
    """Get the permissions (actions) for a list of roles.

    Args:
        role_names: A list of role names or a single role name.

    Returns:
        dict[str, list[PermissionData]]: A dictionary mapping role names to their permissions and scopes.
    """
    permissions_by_role = {}

    for role in roles:
        permissions_by_role[role.external_key] = {
            "permissions": get_permissions_for_single_role(role)
        }

    return permissions_by_role


def get_permissions_for_active_roles_in_scope(
    scope: ScopeData, role: RoleData | None = None
) -> dict[str, dict[str, list[PermissionData | str]]]:
    """Retrieve all permissions granted by the specified roles within the given scope.

    This function operates on the principle that roles defined in policies are templates
    that become active only when assigned to subjects with specific scopes.

    Role Definition vs Role Assignment:

    - Policy roles define potential permissions with namespace patterns (e.g., 'lib^*')
    - Actual permissions are granted only when roles are assigned to subjects with
      concrete scopes (e.g., 'lib^lib:DemoX:CSPROB')
    - The namespace pattern in the policy ('lib^*') indicates the role is designed
      for resources in that namespace, but doesn't grant blanket access
    - The specific scope at assignment time ('lib^lib:DemoX:CSPROB') determines the exact
      resource the permissions apply to

    Behavior:

    - Returns permissions only for roles that have been assigned to subjects
    - Unassigned roles (those defined in policy but not given to any subject)
      contribute no permissions to the result
    - Scope filtering ensures permissions are returned only for the specified
      resource scope, not for the broader namespace pattern

    Returns:
        dict[str, list[PermissionData]]: A dictionary mapping the role external_key to its
        permissions and scopes.
    """
    enforcer = AuthzEnforcer.get_enforcer()
    enforcer.load_policy()
    filtered_policy = enforcer.get_filtered_grouping_policy(
        GroupingPolicyIndex.SCOPE.value, scope.namespaced_key
    )

    if role:
        filtered_policy = [
            policy
            for policy in filtered_policy
            if policy[GroupingPolicyIndex.ROLE.value] == role.namespaced_key
        ]

    return get_permissions_for_roles(
        [
            RoleData(namespaced_key=policy[GroupingPolicyIndex.ROLE.value])
            for policy in filtered_policy
        ]
    )


def get_role_definitions_in_scope(scope: ScopeData) -> list[RoleData]:
    """Get all role definitions available in a specific scope.

    See `get_permissions_for_active_roles_in_scope` for explanation of role
    definitions vs assignments.

    Args:
        scope: The scope to filter roles (e.g., 'lib^*' or '*' for global).

    Returns:
        list[Role]: A list of roles.
    """
    enforcer = AuthzEnforcer.get_enforcer()
    enforcer.load_policy()
    policy_filtered = enforcer.get_filtered_policy(
        PolicyIndex.SCOPE.value, scope.namespaced_key
    )

    permissions_per_role = defaultdict(
        lambda: {
            "permissions": [],
            "scopes": [],
        }
    )
    for policy in policy_filtered:
        permissions_per_role[policy[PolicyIndex.ROLE.value]]["scopes"].append(
            ScopeData(namespaced_key=policy[PolicyIndex.SCOPE.value])
        )  # TODO: I don't think this actually gets used anywhere
        permissions_per_role[policy[PolicyIndex.ROLE.value]]["permissions"].append(
            get_permission_from_policy(policy)
        )

    return [
        RoleData(
            namespaced_key=role,
            permissions=permissions["permissions"],
        )
        for role, permissions in permissions_per_role.items()
    ]


def get_all_roles_names() -> list[str]:
    """Get all the available roles names in the current environment.

    Returns:
        list[str]: A list of role names.
    """
    return AuthzEnforcer.get_enforcer().get_all_subjects()


def get_all_roles_in_scope(scope: ScopeData) -> list[list[str]]:
    """Get all the available role grouping policies in a specific scope.

    Args:
        scope: The scope to filter roles (e.g., 'lib^*' or '*' for global).

    Returns:
        list[list[str]]: A list of policies in the specified scope.
    """
    enforcer = AuthzEnforcer.get_enforcer()
    enforcer.load_policy()
    return enforcer.get_filtered_grouping_policy(
        GroupingPolicyIndex.SCOPE.value, scope.namespaced_key
    )


def assign_role_to_subject_in_scope(
    subject: SubjectData, role: RoleData, scope: ScopeData
) -> bool:
    """Assign a role to a subject.

    Args:
        subject: The ID of the subject.
        role: The role to assign.
        scope: The scope to assign the role to.

    Returns:
        bool: True if the role was assigned successfully, False otherwise.
    """
    enforcer = AuthzEnforcer.get_enforcer()
    enforcer.load_policy()
    return enforcer.add_role_for_user_in_domain(
        subject.namespaced_key,
        role.namespaced_key,
        scope.namespaced_key,
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
) -> bool:
    """Unassign a role from a subject.

    Args:
        subject: The ID of the subject.
        role: The role to unassign.
        scope: The scope from which to unassign the role.

    Returns:
        bool: True if the role was unassigned successfully, False otherwise.
    """
    enforcer = AuthzEnforcer.get_enforcer()
    enforcer.load_policy()
    return enforcer.delete_roles_for_user_in_domain(
        subject.namespaced_key, role.namespaced_key, scope.namespaced_key
    )


def batch_unassign_role_from_subjects_in_scope(
    subjects: list[SubjectData], role: RoleData, scope: ScopeData
) -> None:
    """Unassign a role from a list of subjects.

    Args:
        subjects: A list of subject IDs.
        role_name: The external_key of the role.
        scope: The scope from which to unassign the role.
    """
    for subject in subjects:
        unassign_role_from_subject_in_scope(subject, role, scope)


def get_subject_role_assignments(subject: SubjectData) -> list[RoleAssignmentData]:
    """Get all the roles for a subject across all scopes.

    Args:
        subject: The SubjectData object representing the subject (e.g., SubjectData(external_key='john_doe')).

    Returns:
        list[RoleAssignmentData]: A list of role assignments for the subject.
    """
    enforcer = AuthzEnforcer.get_enforcer()
    role_assignments = []
    for policy in enforcer.get_filtered_grouping_policy(
        GroupingPolicyIndex.SUBJECT.value, subject.namespaced_key
    ):
        role = RoleData(namespaced_key=policy[GroupingPolicyIndex.ROLE.value])
        role.permissions = get_permissions_for_single_role(role)

        role_assignments.append(
            RoleAssignmentData(
                subject=subject,
                roles=[role],
                scope=ScopeData(namespaced_key=policy[GroupingPolicyIndex.SCOPE.value]),
            )
        )
    return role_assignments


def get_subject_role_assignments_in_scope(
    subject: SubjectData, scope: ScopeData
) -> list[RoleAssignmentData]:
    """Get the roles for a subject in a specific scope.

    Args:
        subject: The SubjectData object representing the subject (e.g., SubjectData(external_key='john_doe')).
        scope: The ScopeData object representing the scope (e.g., ScopeData(external_key='lib:DemoX:CSPROB')).

    Returns:
        list[RoleAssignmentData]: A list of role assignments for the subject in the scope.
    """
    enforcer = AuthzEnforcer.get_enforcer()
    enforcer.load_policy()
    # TODO: we still need to get the remaining data for the role like email, etc
    role_assignments = []
    for namespaced_key in enforcer.get_roles_for_user_in_domain(
        subject.namespaced_key, scope.namespaced_key
    ):
        role = RoleData(namespaced_key=namespaced_key)
        role_assignments.append(
            RoleAssignmentData(
                subject=subject,
                roles=[
                    RoleData(
                        namespaced_key=namespaced_key,
                        permissions=get_permissions_for_single_role(role),
                    )
                ],
                scope=scope,
            )
        )
    return role_assignments


def get_subject_role_assignments_for_role_in_scope(
    role: RoleData, scope: ScopeData
) -> list[RoleAssignmentData]:
    """Get the subjects assigned to a specific role in a specific scope.

    Args:
        role: The RoleData object representing the role (e.g., RoleData(external_key='library_admin')).
        scope: The ScopeData object representing the scope (e.g., ScopeData(external_key='lib:DemoX:CSPROB')).

    Returns:
        list[RoleAssignmentData]: A list of subjects assigned to the specified role in the specified scope.
    """
    enforcer = AuthzEnforcer.get_enforcer()
    role_assignments = []
    for subject in enforcer.get_users_for_role_in_domain(
        role.namespaced_key, scope.namespaced_key
    ):
        if subject.startswith(f"{RoleData.NAMESPACE}{RoleData.SEPARATOR}"):
            # Skip roles that are also subjects
            continue

        role_assignments.append(
            RoleAssignmentData(
                subject=SubjectData(namespaced_key=subject),
                roles=[
                    RoleData(
                        namespaced_key=role.namespaced_key,
                        permissions=get_permissions_for_single_role(role),
                    )
                ],
                scope=scope,
            )
        )

    return role_assignments


def get_all_subject_role_assignments_in_scope(
    scope: ScopeData,
) -> list[RoleAssignmentData]:
    """Get all the subjects assigned to any role in a specific scope.

    Args:
        scope: The ScopeData object representing the scope (e.g., ScopeData(external_key='lib:DemoX:CSPROB')).

    Returns:
        list[RoleAssignmentData]: A list of role assignments for all subjects in the specified scope.
    """
    role_assignments_per_subject = {}
    roles_in_scope = get_all_roles_in_scope(scope)

    for policy in roles_in_scope:
        subject = SubjectData(namespaced_key=policy[GroupingPolicyIndex.SUBJECT.value])
        role = RoleData(namespaced_key=policy[GroupingPolicyIndex.ROLE.value])
        role.permissions = get_permissions_for_single_role(role)

        if subject.external_key in role_assignments_per_subject:
            role_assignments_per_subject[subject.external_key].roles.append(role)
            continue

        role_assignments_per_subject[subject.external_key] = RoleAssignmentData(
            subject=subject,
            roles=[role],
            scope=scope,
        )

    return list(role_assignments_per_subject.values())


def get_subjects_for_role(role: RoleData) -> list[SubjectData]:
    """Get all the subjects assigned to a specific role.

    Args:
        role (RoleData): The role to filter subjects.

    Returns:
        list[SubjectData]: A list of subjects assigned to the specified role.
    """
    enforcer = AuthzEnforcer.get_enforcer()
    enforcer.load_policy()
    policies = enforcer.get_filtered_grouping_policy(GroupingPolicyIndex.ROLE.value, role.namespaced_key)
    return [SubjectData(namespaced_key=policy[GroupingPolicyIndex.SUBJECT.value]) for policy in policies]
