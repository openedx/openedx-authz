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
class ScopeData:
    """A scope is a context in which roles and permissions are assigned.

    Attributes:
        scope_id: The scope identifier (e.g., 'org:Demo').

    This class assumes that the scope is already namespaced appropriately
    before being passed in, as scopes can vary widely (e.g., courses, organizations).
    """
    scope_id: str

@define
class ContentLibraryData(ScopeData):
    """A content library is a collection of content items.

    Attributes:
        library_id: The content library identifier (e.g., 'library-v1:edX+DemoX+2021_T1').
    """

    library_id: str

    def __attrs_post_init__(self):
        """Ensure scope ID has 'lib:' namespace prefix."""
        if not self.scope_id.startswith("lib:"):
            self.scope_id = f"lib:{self.library_id}"

@define
class SubjectData:
    """A subject is an entity that can be assigned roles and permissions.

    Attributes:
        subject_id: The subject identifier namespaced (e.g., 'user:john_doe').

    This class assumes that the subject was already namespaced by their own
    type (e.g., 'user:', 'group:') before being passed in since subjects can be
    users, groups, or other entities.
    """

    subject_id: str = ""

@define
class UserData(SubjectData):
    """A user is a subject that can be assigned roles and permissions.

    Attributes:
        username: The username for the user (e.g., 'john_doe').

    This class automatically adds the 'user:' namespace prefix to the subject ID.
    Can be initialized with either username= or subject_id= parameter.
    """

    username: str = ""

    def __attrs_post_init__(self):
        """Ensure subject ID has 'user:' namespace prefix."""
        # If username was provided, use it to set subject_id
        if not self.subject_id.startswith("user:"):
            self.subject_id = f"user:{self.username}"

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
            self.action_id = f"act:{self.action_id}"


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
            self.name = f"role:{self.name}"


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
