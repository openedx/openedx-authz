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
class UserData:
    """A user is a subject that can be assigned roles and permissions.

    Attributes:
        username: The username. Automatically prefixed with 'user:' if not present.
    """

    username: str

    def __attrs_post_init__(self):
        """Ensure username has 'user:' namespace prefix."""
        if not self.username.startswith("user:"):
            object.__setattr__(self, "username", f"user:{self.username}")


@define
class ScopeData:
    """A scope is a context in which roles and permissions are assigned.

    Attributes:
        scope_id: The scope identifier (e.g., 'course-v1:edX+DemoX+2021_T1').

    This class assumes that the scope is already namespaced appropriately
    before being passed in, as scopes can vary widely (e.g., courses, organizations).
    """
    # TODO: figure out namespace for scopes
    scope_id: str


@define
class SubjectData:
    """A subject is an entity that can be assigned roles and permissions.

    Attributes:
        subject_id: The subject identifier namespaced (e.g., 'user:john_doe').

    This class assumes that the subject was already namespaced by their own
    type (e.g., 'user:', 'group:') before being passed in since subjects can be
    users, groups, or other entities.
    """

    subject_id: str


@define
class ActionData:
    """An action is an operation that can be performed in a specific scope.

    Attributes:
        action: The action name. Automatically prefixed with 'act:' if not present.
    """

    action_id: str

    def __attrs_post_init__(self):
        """Ensure action name has 'act:' namespace prefix."""
        if not self.action_id.startswith("act:"):
            object.__setattr__(self, "action_id", f"act:{self.action_id}")


@define
class PermissionData:  # TODO: change to policy?
    """A permission is an action that can be performed under certain conditions.

    Attributes:
        name: The name of the permission.
    """

    action: ActionData
    effect: Literal["allow", "deny"] = "allow"


@define
class RoleMetadataData:
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
class RoleData:
    """A role is a named group of permissions.

    Attributes:
        name: The name of the role. Must have 'role:' namespace prefix.
        permissions: A list of permissions assigned to the role.
        scopes: A list of scopes assigned to the role.
        metadata: A dictionary of metadata assigned to the role. This can include
            information such as the description of the role, creation date, etc.
    """

    name: str
    permissions: list[PermissionData] = None
    metadata: RoleMetadataData = None

    def __attrs_post_init__(self):
        """Ensure role name has 'role:' namespace prefix."""
        if not self.name.startswith("role:"):
            object.__setattr__(self, "name", f"role:{self.name}")


@define
class RoleAssignmentData:
    """A role assignment is the assignment of a role to a subject in a specific scope.

    Attributes:
        subject: The ID of the user namespaced (e.g., 'user:john_doe').
        email: The email of the user.
        role_name: The name of the role.
        scope: The scope in which the role is assigned.
    """

    subject: SubjectData
    role: RoleData
    scope: ScopeData
