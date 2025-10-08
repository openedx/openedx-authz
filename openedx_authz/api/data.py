"""Data classes and enums for representing roles, permissions, and policies."""

from enum import Enum
from typing import ClassVar, Literal, Type

from attrs import define
from opaque_keys import InvalidKeyError
from opaque_keys.edx.locator import LibraryLocatorV2

__all__ = [
    "UserData",
    "PermissionData",
    "GroupingPolicyIndex",
    "PolicyIndex",
    "ActionData",
    "RoleAssignmentData",
    "RoleData",
    "ScopeData",
    "SubjectData",
]

AUTHZ_POLICY_ATTRIBUTES_SEPARATOR = "^"
EXTERNAL_KEY_SEPARATOR = ":"


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

    SEPARATOR: ClassVar[str] = AUTHZ_POLICY_ATTRIBUTES_SEPARATOR
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
        """
        if not self.NAMESPACE:
            # No namespace defined, nothing to do
            return

        # Case 1: Initialized with external_key only, derive namespaced_key
        if self.external_key and not self.namespaced_key:
            self.namespaced_key = f"{self.NAMESPACE}{self.SEPARATOR}{self.external_key}"

        # Case 2: Initialized with namespaced_key only, derive external_key
        if not self.external_key and self.namespaced_key:
            self.external_key = self.namespaced_key.split(self.SEPARATOR, 1)[1]

        # Case 3: Neither provided, raise error
        if not self.external_key and not self.namespaced_key:
            raise ValueError("Either external_key or namespaced_key must be provided.")


class ScopeMeta(type):
    """Metaclass for ScopeData to handle dynamic subclass instantiation based on namespace."""

    scope_registry: ClassVar[dict[str, Type["ScopeData"]]] = {}

    def __init__(cls, name, bases, attrs):
        """Initialize the metaclass and register subclasses."""
        super().__init__(name, bases, attrs)
        if not hasattr(cls, "scope_registry"):
            cls.scope_registry = {}
        cls.scope_registry[cls.NAMESPACE] = cls

    def __call__(cls, *args, **kwargs):
        """Instantiate the appropriate subclass based on the namespace in namespaced_key.

        There are two ways to instantiate:
        1. By providing external_key= and format for the external key determines the subclass
        (e.g., 'lib^any-library' = ContentLibraryData).
        2. By providing namespaced_key= and the class is determined from the namespace prefix
        in namespaced_key (e.g., 'lib@any-library' = ContentLibraryData).

        The namespaced key is usually used when getting objects from the policy store,
        while the external key is usually used when initializing from user input or API calls. For example,
        when creating a role assignment for a content library, the API call would provide the library ID
        (external_key) and the system would need to determine the correct scope subclass based on the
        format of the library ID. While when retrieving role assignments from the policy store, the
        namespaced_key would be used to determine the subclass.
        """
        if cls is not ScopeData:
            return super().__call__(*args, **kwargs)

        if "namespaced_key" in kwargs:
            scope_cls = cls.get_subclass_by_namespaced_key(kwargs["namespaced_key"])
            return super(ScopeMeta, scope_cls).__call__(*args, **kwargs)

        if "external_key" in kwargs:
            scope_cls = cls.get_subclass_by_external_key(kwargs["external_key"])
            return super(ScopeMeta, scope_cls).__call__(*args, **kwargs)

        return super().__call__(*args, **kwargs)

    @classmethod
    def get_subclass_by_namespaced_key(mcs, namespaced_key: str) -> Type["ScopeData"]:
        """Get the appropriate subclass based on the namespace in namespaced_key.

        Args:
            namespaced_key: The namespaced key (e.g., 'lib^any-library').

        Returns:
            The subclass of ScopeData corresponding to the namespace, or ScopeData if not found.
        """
        # TODO: Default separator, can't access directly from class so made it a constant
        namespace = namespaced_key.split(AUTHZ_POLICY_ATTRIBUTES_SEPARATOR, 1)[0]
        return mcs.scope_registry.get(namespace, ScopeData)

    @classmethod
    def get_subclass_by_external_key(mcs, external_key: str) -> Type["ScopeData"]:
        """Get the appropriate subclass based on the format of external_key.

        Args:
            external_key: The external key (e.g., 'lib:any-library').

        Returns:
            The subclass of ScopeData corresponding to the namespace, or ScopeData if not found.
        """
        # Here we need to assume a couple of things:
        # 1. The external_key is always in the format 'namespace...:other things'. E.g., 'lib:any-library',
        # even 'course-v1:edX+DemoX+2021_T1'. This won't work for org scopes because they don't explicitly indicate
        # the namespace in the external key. TODO: We need to handle org scopes differently.
        # 2. The namespace is always the part before the first separator.
        # 3. If the namespace is not recognized, we raise an error.
        # 4. The subclass implements a validation method to validate the entire key. E.g., ContentLibraryData
        # validates that the external_key is a valid library ID.
        if EXTERNAL_KEY_SEPARATOR not in external_key:
            raise ValueError(f"Invalid external_key format: {external_key}")

        namespace = external_key.split(EXTERNAL_KEY_SEPARATOR, 1)[0]
        scope_subclass = mcs.scope_registry.get(namespace)

        if not scope_subclass:
            raise ValueError(
                f"Unknown scope: {namespace} for external_key: {external_key}"
            )

        if not scope_subclass.validate_external_key(external_key):
            raise ValueError(f"Invalid external_key format: {external_key}")

        return scope_subclass

    @classmethod
    def validate_external_key(mcs, external_key: str) -> bool:
        """Validate the external_key format for the subclass.

        Args:
            external_key: The external key to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        raise NotImplementedError(
            "Subclasses must implement validate_external_key method."
        )


@define
class ScopeData(AuthZData, metaclass=ScopeMeta):
    """A scope is a context in which roles and permissions are assigned.

    Attributes:
        namespaced_key: The scope identifier (e.g., 'org@Demo').
    """

    NAMESPACE: ClassVar[str] = "sc"

    @classmethod
    def validate_external_key(cls, _: str) -> bool:
        """Validate the external_key format for ScopeData.

        For the base ScopeData class, we accept any external_key works. This
        is only implemented for the sake of completeness. Subclasses should
        implement their own validation logic.

        Args:
            external_key: The external key to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        return True


@define
class ContentLibraryData(ScopeData):
    """A content library is a collection of content items.

    Attributes:
        library_id: The content library identifier (e.g., 'library-v1:edX+DemoX+2021_T1').
        namespaced_key: Inherited from ScopeData, auto-generated from name if not provided.

    TODO: this class should live alongside library definitions and not here.
    """

    NAMESPACE: ClassVar[str] = "lib"

    @property
    def library_id(self) -> str:
        """The library identifier as used in Open edX (e.g., 'math_101', 'library-v1:edX+DemoX').

        This is an alias for external_key that represents the library ID without the namespace prefix.

        Returns:
            str: The library identifier without namespace.
        """
        return self.external_key

    @classmethod
    def validate_external_key(cls, external_key: str) -> bool:
        """Validate the external_key format for ContentLibraryData.

        Args:
            external_key: The external key to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        try:
            LibraryLocatorV2.from_string(external_key)
            return True
        except InvalidKeyError:
            return False

    def __str__(self):
        """Human readable string representation of the content library."""
        return self.library_id

    def __repr__(self):
        """Developer friendly string representation of the content library."""
        return self.namespaced_key


class SubjectMeta(type):
    """Metaclass for SubjectData to handle dynamic subclass instantiation based on namespace."""

    subject_registry: ClassVar[dict[str, Type["SubjectData"]]] = {}

    def __init__(cls, name, bases, attrs):
        """Initialize the metaclass and register subclasses."""
        super().__init__(name, bases, attrs)
        if not hasattr(cls, "subject_registry"):
            cls.subject_registry = {}
        cls.subject_registry[cls.NAMESPACE] = cls

    def __call__(cls, *args, **kwargs):
        """Instantiate the appropriate subclass based on the namespace in namespaced_key.

        There are two ways to instantiate:
        1. By providing external_key= and format for the external key determines the subclass.
        2. By providing namespaced_key= and the class is determined from the namespace prefix
        in namespaced_key (e.g., 'user^alice' = UserData).

        TODO: we can't currently instantiate by external_key because we don't have a way to
        determine the subclass from the external_key format. A temporary solution is to
        use the users.py module to instantiate UserData directly when needed.
        """
        if cls is SubjectData and "namespaced_key" in kwargs:
            subject_cls = cls.get_subclass_by_namespaced_key(kwargs["namespaced_key"])
            return super(SubjectMeta, subject_cls).__call__(*args, **kwargs)

        return super().__call__(*args, **kwargs)

    @classmethod
    def get_subclass_by_namespaced_key(mcs, namespaced_key: str) -> Type["SubjectData"]:
        """Get the appropriate subclass based on the namespace in namespaced_key.

        Args:
            namespaced_key: The namespaced key (e.g., 'user^alice').

        Returns:
            The subclass of SubjectData corresponding to the namespace, or SubjectData if not found.
        """
        namespace = namespaced_key.split(AUTHZ_POLICY_ATTRIBUTES_SEPARATOR, 1)[0]
        return mcs.subject_registry.get(namespace, SubjectData)


@define
class SubjectData(AuthZData, metaclass=SubjectMeta):
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

    def __str__(self):
        """Human readable string representation of the user."""
        return self.username

    def __repr__(self):
        """Developer friendly string representation of the user."""
        return self.namespaced_key


@define
class ActionData(AuthZData):
    """An action is an operation that can be performed in a specific scope.

    Attributes:
        action: The action name. Automatically prefixed with 'act@' if not present.
    """

    NAMESPACE: ClassVar[str] = "act"

    @property
    def name(self) -> str:
        """The human-readable name of the action (e.g., 'Delete Library', 'Edit Content').

        This property transforms the external_key into a human-readable display name
        by replacing underscores with spaces and capitalizing each word.

        Returns:
            str: The human-readable action name (e.g., 'Delete Library').
        """
        return self.external_key.replace("_", " ").title()

    def __str__(self):
        """Human readable string representation of the action."""
        return self.name

    def __repr__(self):
        """Developer friendly string representation of the action."""
        return self.namespaced_key


@define
class PermissionData:
    """A permission is an action that can be performed under certain conditions.

    Attributes:
        name: The name of the permission.
    """

    action: ActionData = None
    effect: Literal["allow", "deny"] = "allow"

    def __str__(self):
        """Human readable string representation of the permission and its effect."""
        return f"{self.action} - {self.effect}"

    def __repr__(self):
        """Developer friendly string representation of the permission."""
        return f"{self.action.namespaced_key} => {self.effect}"


@define
class RoleData(AuthZData):
    """A role is a named group of permissions.

    Attributes:
        name: The name of the role. Must have 'role@' namespace prefix.
        permissions: A list of permissions assigned to the role.
    """

    NAMESPACE: ClassVar[str] = "role"
    permissions: list[PermissionData] = []

    @property
    def name(self) -> str:
        """The human-readable name of the role (e.g., 'Library Admin', 'Course Instructor').

        This property transforms the external_key into a human-readable display name
        by replacing underscores with spaces and capitalizing each word.

        Returns:
            str: The human-readable role name (e.g., 'Library Admin').
        """
        return self.external_key.replace("_", " ").title()

    def __str__(self):
        """Human readable string representation of the role and its permissions."""
        return f"{self.name}: {', '.join(str(p) for p in self.permissions)}"

    def __repr__(self):
        """Developer friendly string representation of the role."""
        return self.namespaced_key


@define
class RoleAssignmentData:
    """A role assignment is the assignment of a role to a subject in a specific scope.

    Attributes:
        subject: The subject to whom the role is assigned (e.g., user or service).
        role: The role being assigned.
        scope: The scope in which the role is assigned (e.g., organization, course).
    """

    subject: SubjectData = None  # Needs defaults to avoid value error from attrs
    roles: list[RoleData] = []
    scope: ScopeData = None

    def __str__(self):
        """Human readable string representation of the role assignment."""
        role_names = ", ".join(role.name for role in self.roles)
        return f"{self.subject} => {role_names} @ {self.scope}"

    def __repr__(self):
        """Developer friendly string representation of the role assignment."""
        role_keys = ", ".join(role.namespaced_key for role in self.roles)
        return f"{self.subject.namespaced_key} => [{role_keys}] @ {self.scope.namespaced_key}"
