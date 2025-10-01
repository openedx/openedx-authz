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
class AuthZData:
    """Base class for all authz data classes.

    Attributes:
        NAMESPACE: The namespace prefix for the data type (e.g., 'user', 'role').
        SEPARATOR: The separator between the namespace and the identifier (e.g., ':', '@').

    Subclasses are automatically registered by their NAMESPACE for factory pattern.
    """

    SEPARATOR: str = "@"
    NAMESPACE: str = None

    # TODO: Implement factory method to return correct subclass based on NAMESPACE prefix.
    # This would allow initializing with either subject or scope, etc. and returning the correct subclass.
    # So we don't have to manage each subclass separately or hardcoded anywhere.


@define
class ScopeData(AuthZData):
    """A scope is a context in which roles and permissions are assigned.

    Attributes:
        scope_id: The scope identifier (e.g., 'org@Demo').

    Acts as a factory: automatically returns the correct subclass based on the scope_id prefix.
    """

    NAMESPACE: str = "sc"
    scope_id: str = ""
    name: str = ""

    def __attrs_post_init__(self):
        """Ensure scope ID has appropriate namespace prefix."""
        if not self.scope_id:
            self.scope_id = f"{self.NAMESPACE}{self.SEPARATOR}{self.name}".lower()

        # Allow reverse lookup of name from scope_id
        if (
            not self.name
            and self.scope_id
            and self.NAMESPACE
            and self.scope_id.startswith(f"{self.NAMESPACE}{self.SEPARATOR}")
        ):
            self.name = self.scope_id.split(self.SEPARATOR, 1)[1].lower()


@define
class ContentLibraryData(ScopeData):
    """A content library is a collection of content items.

    Attributes:
        library_id: The content library identifier (e.g., 'library-v1:edX+DemoX+2021_T1').
        scope_id: Inherited from ScopeData, auto-generated from library_id if not provided.
    """

    NAMESPACE: str = "lib"
    library_id: str = ""

    def __attrs_post_init__(self):
        """Ensure scope ID has 'lib@' namespace prefix."""
        if not self.scope_id:
            self.scope_id = f"{self.NAMESPACE}{self.SEPARATOR}{self.library_id}".lower()

        # Allow reverse lookup of library_id from scope_id
        if not self.library_id and self.scope_id.startswith(
            f"{self.NAMESPACE}{self.SEPARATOR}"
        ):
            self.library_id = self.scope_id.split(self.SEPARATOR, 1)[1].lower()


@define
class SubjectData(AuthZData):
    """A subject is an entity that can be assigned roles and permissions.

    Attributes:
        subject_id: The subject identifier namespaced (e.g., 'user@john_doe').

    Acts as a factory: automatically returns the correct subclass based on the subject_id prefix.
    """

    NAMESPACE: str = "sub"
    subject_id: str = ""
    name: str = ""

    def __attrs_post_init__(self):
        """Ensure subject ID has appropriate namespace prefix."""
        if not self.subject_id:
            self.subject_id = f"{self.NAMESPACE}{self.SEPARATOR}{self.name}".lower()

        # Allow reverse lookup of name from subject_id
        if not self.name and self.subject_id.startswith(
            f"{self.NAMESPACE}{self.SEPARATOR}"
        ):
            self.name = self.subject_id.split(self.SEPARATOR, 1)[1].lower()


@define
class UserData(SubjectData):
    """A user is a subject that can be assigned roles and permissions.

    Attributes:
        username: The username for the user (e.g., 'john_doe').
        subject_id: Inherited from SubjectData, auto-generated from username if not provided.

    This class automatically adds the 'user@' namespace prefix to the subject ID.
    Can be initialized with either username= or subject_id= parameter.
    """

    NAMESPACE: str = "user"
    username: str = ""

    def __attrs_post_init__(self):
        """Ensure subject ID has 'user@' namespace prefix.

        This allows initialization with either username or subject_id.
        """
        if not self.subject_id:
            self.subject_id = f"{self.NAMESPACE}{self.SEPARATOR}{self.username}".lower()

        # Allow reverse lookup of username from subject_id
        if not self.username and self.subject_id.startswith(
            f"{self.NAMESPACE}{self.SEPARATOR}"
        ):
            self.username = self.subject_id.split(self.SEPARATOR, 1)[1].lower()


@define
class ActionData(AuthZData):
    """An action is an operation that can be performed in a specific scope.

    Attributes:
        action: The action name. Automatically prefixed with 'act@' if not present.
    """

    NAMESPACE: str = "act"
    name: str = ""
    action_id: str = ""

    def __attrs_post_init__(self):
        """Ensure action name has 'act@' namespace prefix.

        This allows initialization with either name= or action_id= parameter.
        """
        if not self.action_id:
            self.action_id = f"{self.NAMESPACE}{self.SEPARATOR}{self.name}".lower()

        # Allow reverse lookup of name from action_id
        if not self.name and self.action_id.startswith(
            f"{self.NAMESPACE}{self.SEPARATOR}"
        ):
            self.name = self.action_id.split(self.SEPARATOR, 1)[1].lower()


@define
class PermissionData(AuthZData):
    """A permission is an action that can be performed under certain conditions.

    Attributes:
        name: The name of the permission.
    """

    action: ActionData = None
    effect: Literal["allow", "deny"] = "allow"


@define
class RoleMetadataData(AuthZData):
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
class RoleData(AuthZData):
    """A role is a named group of permissions.

    Attributes:
        name: The name of the role. Must have 'role@' namespace prefix.
        role_id: The role identifier namespaced (e.g., 'role@instructor').
        permissions: A list of permissions assigned to the role.
        metadata: A dictionary of metadata assigned to the role. This can include
            information such as the description of the role, creation date, etc.
    """

    NAMESPACE: str = "role"
    name: str = ""
    role_id: str = ""
    permissions: list[PermissionData] = None
    metadata: RoleMetadataData = None

    def __attrs_post_init__(self):
        """Ensure role id has 'role@' namespace prefix.

        This allows initialization with either name= or role_id= parameter.
        """
        if not self.role_id or not self.role_id.startswith(
            f"{self.NAMESPACE}{self.SEPARATOR}"
        ):
            self.role_id = f"{self.NAMESPACE}{self.SEPARATOR}{self.name}".lower()

        # Allow reverse lookup of name from role_id
        if not self.name and self.role_id.startswith(
            f"{self.NAMESPACE}{self.SEPARATOR}"
        ):
            self.name = self.role_id.split(self.SEPARATOR, 1)[1].lower()


@define
class RoleAssignmentData(AuthZData):
    """A role assignment is the assignment of a role to a subject in a specific scope.

    Attributes:
        subject: The ID of the user namespaced (e.g., 'user@john_doe').
        email: The email of the user.
        role_name: The name of the role.
        scope: The scope in which the role is assigned.
    """

    subject: SubjectData = None
    role: RoleData = None
    scope: ScopeData = None
