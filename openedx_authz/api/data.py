"""Data classes and enums for representing roles, permissions, and policies."""

from enum import Enum
from typing import Literal

from attrs import define


class GroupingPolicyIndex(Enum):
    """Index of fields in a grouping policy."""

    SUBJECT = 0
    ROLE = 1
    SCOPE = 2
    # The rest of the fields are optional and can be ignored for now


class PolicyIndex(Enum):
    """Index of fields in a policy."""

    ROLE = 0
    ACT = 1
    SCOPE = 2
    EFFECT = 3
    # The rest of the fields are optional and can be ignored for now


@define
class Permission:  # TODO: change to policy?
    """A permission is an action that can be performed under certain conditions.

    Attributes:
        name: The name of the permission.
    """

    # TODO: what other attributes should a permission have?
    name: str
    effect: Literal["allow", "deny"] = "allow"


@define
class RoleMetadata:
    """Metadata for a role.

    Attributes:
        description: A description of the role.
        created_at: The date and time the role was created.
        created_by: The ID of the subject who created the role.
    """

    description: str = None
    created_at: str = None
    created_by: str = None


@define
class Role:
    """A role is a named group of permissions.

    Attributes:
        name: The name of the role.
        permissions: A list of permissions assigned to the role.
        scopes: A list of scopes assigned to the role.
        metadata: A dictionary of metadata assigned to the role. This can include
            information such as the description of the role, creation date, etc.
    """

    name: str
    scopes: list[str]
    permissions: list[Permission] = None
    metadata: RoleMetadata = None


@define
class RoleAssignment:
    """A role assignment is the assignment of a role to a subject in a specific scope.

    Attributes:
        subject: The ID of the user namespaced (e.g., 'user:john_doe').
        email: The email of the user.
        role_name: The name of the role.
        scope: The scope in which the role is assigned.
    """

    subject: str  # TODO: I think here it makes sense to sanitize the subject so it's the username?
    role: Role
