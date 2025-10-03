"""Data classes and enums for representing roles, permissions, and policies."""

from enum import Enum
from typing import ClassVar, Literal, Type

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


class AuthzBaseClass:
    """Base class for all authz classes.

    Attributes:
        SEPARATOR: The separator between the namespace and the identifier (e.g., ':', '@').
        NAMESPACE: The namespace prefix for the data type (e.g., 'user', 'role').
    """

    SEPARATOR: ClassVar[str] = "^"
    NAMESPACE: ClassVar[str] = None

@define
class AuthZData(AuthzBaseClass):
    """Base class for all authz data classes.

    Attributes:
        NAMESPACE: The namespace prefix for the data type (e.g., 'user', 'role').
        SEPARATOR: The separator between the namespace and the identifier (e.g., ':', '@').
        external_key: The ID for the object outside of the authz system (e.g., username).
            Could also be used for human-readable names (e.g., role or action name).
        namespaced_key: The ID for the object within the authz system (e.g., 'user@john_doe').
    """

    external_key: str = ""
    namespaced_key: str = ""

    def __attrs_post_init__(self):
        """Post-initialization processing for attributes.

        This method ensures that either external_key or namespaced_key is provided,
        and derives the other attribute based on the NAMESPACE and SEPARATOR.

        Note:
        I will always instantiate with either external_key or namespaced_key, never both.
        So we need to derive the other one based on the NAMESPACE.
        """
        if self.NAMESPACE and not self.namespaced_key:
            self.namespaced_key = f"{self.NAMESPACE}{self.SEPARATOR}{self.external_key}"

        if self.NAMESPACE and not self.external_key and self.namespaced_key:
            self.external_key = self.namespaced_key.split(self.SEPARATOR, 1)[1]


@define
class ScopeData(AuthZData):
    """A scope is a context in which roles and permissions are assigned.

    Attributes:
        namespaced_key: The scope identifier (e.g., 'org@Demo').
    """

    NAMESPACE: ClassVar[str] = "sc"


@define
class ContentLibraryData(ScopeData):
    """A content library is a collection of content items.

    Attributes:
        library_id: The content library identifier (e.g., 'library-v1:edX+DemoX+2021_T1').
        namespaced_key: Inherited from ScopeData, auto-generated from name if not provided.
    """

    NAMESPACE: ClassVar[str] = "lib"
    library_id: str = ""

    @property
    def library_id(self) -> str:
        """The library identifier as used in Open edX (e.g., 'math_101', 'library-v1:edX+DemoX').

        This is an alias for external_key that represents the library ID without the namespace prefix.

        Returns:
            str: The library identifier without namespace.
        """
        return self.external_key


@define
class SubjectData(AuthZData):
    """A subject is an entity that can be assigned roles and permissions.

    Attributes:
        namespaced_key: The subject identifier namespaced (e.g., 'sub@generic').
    """

    NAMESPACE: ClassVar[str] = "sub"

@define
class UserData(SubjectData):
    """A user is a subject that can be assigned roles and permissions.

    Attributes:
        username: The username for the user (e.g., 'john_doe').
        namespaced_key: Inherited from SubjectData, auto-generated from username if not provided.

    This class automatically adds the 'user@' namespace prefix to the subject ID.
    Can be initialized with either external_key= or namespaced_key= parameter.
    """

    NAMESPACE: ClassVar[str] = "user"

    @property
    def username(self) -> str:
        """The username for the user (e.g., 'john_doe').

        This is an alias for external_key that represents the username without the namespace prefix.

        Returns:
            str: The username without namespace.
        """
        return self.external_key


@define
class ActionData(AuthZData):
    """An action is an operation that can be performed in a specific scope.

    Attributes:
        action: The action name. Automatically prefixed with 'act@' if not present.
    """

    NAMESPACE: ClassVar[str] = "act"
    name: str = ""

    @property
    def name(self) -> str:
        """The human-readable name of the action (e.g., 'Delete Library', 'Edit Content').

        This property transforms the external_key into a human-readable display name
        by replacing underscores with spaces and capitalizing each word.

        Returns:
            str: The human-readable action name (e.g., 'Delete Library').
        """
        return self.external_key.replace("_", " ").title()


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

    NAMESPACE: ClassVar[str] = "role"
    permissions: list[PermissionData] = None
    metadata: RoleMetadataData = None

    @property
    def name(self) -> str:
        """The human-readable name of the role (e.g., 'Library Admin', 'Course Instructor').

        This property transforms the external_key into a human-readable display name
        by replacing underscores with spaces and capitalizing each word.

        Returns:
            str: The human-readable role name (e.g., 'Library Admin').
        """
        return self.external_key.replace("_", " ").title()


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
