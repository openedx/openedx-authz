"""Data classes and enums for representing roles, permissions, and policies."""

import re
from abc import abstractmethod
from enum import Enum
from typing import ClassVar, Literal, Type

from attrs import define
from opaque_keys import InvalidKeyError
from opaque_keys.edx.locator import LibraryLocatorV2

try:
    from openedx.core.djangoapps.content_libraries.models import ContentLibrary
except ImportError:
    ContentLibrary = None

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
    "ContentLibraryData",
]

AUTHZ_POLICY_ATTRIBUTES_SEPARATOR = "^"
EXTERNAL_KEY_SEPARATOR = ":"
GENERIC_SCOPE_WILDCARD = "*"
NAMESPACED_KEY_PATTERN = rf"^.+{re.escape(AUTHZ_POLICY_ATTRIBUTES_SEPARATOR)}.+$"


class GroupingPolicyIndex(Enum):
    """Index positions for fields in a Casbin grouping policy (g or g2).

    Grouping policies represent role assignments that link subjects to roles within scopes.
    Format: [subject, role, scope, ...]

    Attributes:
        SUBJECT: Position 0 - The subject identifier (e.g., 'user^john_doe').
        ROLE: Position 1 - The role identifier (e.g., 'role^instructor').
        SCOPE: Position 2 - The scope identifier (e.g., 'lib^lib:DemoX:CSPROB').

    Note:
        Additional fields beyond position 2 are optional and currently ignored.
    """

    SUBJECT = 0
    ROLE = 1
    SCOPE = 2
    # The rest of the fields are optional and can be ignored for now


class PolicyIndex(Enum):
    """Index positions for fields in a Casbin policy (p).

    Policies define permissions by linking roles to actions within scopes with an effect.
    Format: [role, action, scope, effect, ...]

    Attributes:
        ROLE: Position 0 - The role identifier (e.g., 'role^instructor').
        ACT: Position 1 - The action identifier (e.g., 'act^read').
        SCOPE: Position 2 - The scope identifier (e.g., 'lib^lib:DemoX:CSPROB').
        EFFECT: Position 3 - The effect, either 'allow' or 'deny'.

    Note:
        Additional fields beyond position 3 are optional and currently ignored.
    """

    ROLE = 0
    ACT = 1
    SCOPE = 2
    EFFECT = 3
    # The rest of the fields are optional and can be ignored for now


class AuthzBaseClass:
    """Base class for all authz classes.

    Attributes:
        SEPARATOR: The separator between the namespace and the identifier (default: '^').
        NAMESPACE: The namespace prefix for the data type (e.g., 'user', 'role', 'act', 'lib').
    """

    SEPARATOR: ClassVar[str] = AUTHZ_POLICY_ATTRIBUTES_SEPARATOR
    NAMESPACE: ClassVar[str] = None


@define
class AuthZData(AuthzBaseClass):
    """Base class for all authz data classes.

    Attributes:
        NAMESPACE: The namespace prefix for the data type (e.g., 'user', 'role', 'act', 'lib').
        SEPARATOR: The separator between the namespace and the identifier (default: '^').
        external_key: The ID for the object outside of the authz system (e.g., 'john_doe' for a user,
            'instructor' for a role, 'lib:DemoX:CSPROB' for a content library).
        namespaced_key: The ID for the object within the authz system, combining namespace and external_key
            (e.g., 'user^john_doe', 'role^instructor', 'lib^lib:DemoX:CSPROB').

    Examples:
        >>> user = UserData(external_key='john_doe')
        >>> user.namespaced_key
        'user^john_doe'
        >>> role = RoleData(namespaced_key='role^instructor')
        >>> role.external_key
        'instructor'
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

        if not self.external_key and not self.namespaced_key:
            raise ValueError("Either external_key or namespaced_key must be provided.")

        # Case 1: Initialized with external_key only, derive namespaced_key
        if not self.namespaced_key:
            self.namespaced_key = f"{self.NAMESPACE}{self.SEPARATOR}{self.external_key}"

        # Case 2: Initialized with namespaced_key only, derive external_key. Assume valid format for
        # namespaced_key at this point.
        if not self.external_key:
            self.external_key = self.namespaced_key.split(self.SEPARATOR, 1)[1]


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
        """Instantiate the appropriate ScopeData subclass dynamically.

        This metaclass enables polymorphic instantiation based on either the external_key
        format or the namespaced_key prefix, automatically returning the correct subclass.

        Instantiation modes:
            1. external_key: Determines subclass from the key format. The namespace prefix
               before the first ':' is used to look up the appropriate subclass.
               Example: ScopeData(external_key='lib:DemoX:CSPROB') → ContentLibraryData

            2. namespaced_key: Determines subclass from the namespace prefix before '^'.
               Example: ScopeData(namespaced_key='lib^lib:DemoX:CSPROB') → ContentLibraryData

        Usage patterns:
            - namespaced_key: Used when retrieving objects from the policy store
            - external_key: Used when initializing from user input or API calls

        Examples:
            >>> # From external key (e.g., API input)
            >>> scope = ScopeData(external_key='lib:DemoX:CSPROB')
            >>> isinstance(scope, ContentLibraryData)
            True
            >>> # From namespaced key (e.g., policy store)
            >>> scope = ScopeData(namespaced_key='lib^lib:DemoX:CSPROB')
            >>> isinstance(scope, ContentLibraryData)
            True
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
        """Get the appropriate ScopeData subclass from the namespaced key.

        Extracts the namespace prefix (before '^') and returns the registered subclass.

        Args:
            namespaced_key: The namespaced key (e.g., 'lib^lib:DemoX:CSPROB', 'sc^generic').

        Returns:
            The ScopeData subclass for the namespace, or ScopeData if namespace not recognized.

        Examples:
            >>> ScopeMeta.get_subclass_by_namespaced_key('lib^lib:DemoX:CSPROB')
            <class 'ContentLibraryData'>
            >>> ScopeMeta.get_subclass_by_namespaced_key('sc^generic')
            <class 'ScopeData'>
        """
        # TODO: Default separator, can't access directly from class so made it a constant
        if not re.match(NAMESPACED_KEY_PATTERN, namespaced_key):
            raise ValueError(f"Invalid namespaced_key format: {namespaced_key}")

        namespace = namespaced_key.split(AUTHZ_POLICY_ATTRIBUTES_SEPARATOR, 1)[0]
        return mcs.scope_registry.get(namespace, ScopeData)

    @classmethod
    def get_subclass_by_external_key(mcs, external_key: str) -> Type["ScopeData"]:
        """Get the appropriate ScopeData subclass from the external key format.

        Extracts the namespace from the external key (before the first ':') and validates
        the key format using the subclass's validate_external_key method.

        Args:
            external_key: The external key (e.g., 'lib:DemoX:CSPROB', 'sc:generic').

        Returns:
            The ScopeData subclass corresponding to the namespace.

        Raises:
            ValueError: If the external_key format is invalid or namespace is not recognized.

        Examples:
            >>> ScopeMeta.get_subclass_by_external_key('lib:DemoX:CSPROB')
            <class 'ContentLibraryData'>

        Notes:
            - The external_key format should be 'namespace:some-identifier' (e.g., 'lib:DemoX:CSPROB').
            - The namespace prefix before ':' is used to determine the subclass.
            - Each subclass must implement validate_external_key() to verify the full key format.
            - This won't work for org scopes that don't have explicit namespace prefixes.
              TODO: Handle org scopes differently.
        """
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
    def get_all_namespaces(mcs) -> dict[str, Type["ScopeData"]]:
        """Get all registered scope namespaces.

        Returns:
            dict[str, Type["ScopeData"]]: A dictionary of all namespace prefixes registered in the scope registry.
                Each namespace corresponds to a ScopeData subclass (e.g., 'lib', 'sc').

        Examples:
            >>> ScopeMeta.get_all_namespaces()
            {'sc': ScopeData, 'lib': ContentLibraryData, 'org': OrganizationData}
        """
        return mcs.scope_registry

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

    This is the base class for scope types. Specific scope types (like ContentLibraryData)
    are subclasses with their own namespace prefixes. This class is supposed to be generic
    and not tied to any specific scope type, holding attributes common to all scopes.

    Attributes:
        NAMESPACE: 'sc' for generic scopes.
        external_key: The scope identifier without namespace (e.g., 'generic_scope').
        namespaced_key: The scope identifier with namespace (e.g., 'sc^generic_scope').

    Examples:
        >>> scope = ScopeData(external_key='generic_scope')
        >>> scope.namespaced_key
        'sc^generic_scope'
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

    @abstractmethod
    def exists(self) -> bool:
        """Check if the scope exists.

        Returns:
            bool: True if the scope exists, False otherwise.
        """
        raise NotImplementedError("Subclasses must implement exists method.")


@define
class ContentLibraryData(ScopeData):
    """A content library scope for authorization in the Open edX platform.

    Content libraries use the LibraryLocatorV2 format for identification.

    Attributes:
        NAMESPACE: 'lib' for content library scopes.
        external_key: The content library identifier (e.g., 'lib:DemoX:CSPROB').
            Must be a valid LibraryLocatorV2 format.
        namespaced_key: The library identifier with namespace (e.g., 'lib^lib:DemoX:CSPROB').
        library_id: Property alias for external_key.

    Examples:
        >>> library = ContentLibraryData(external_key='lib:DemoX:CSPROB')
        >>> library.namespaced_key
        'lib^lib:DemoX:CSPROB'
        >>> library.library_id
        'lib:DemoX:CSPROB'

    Note:
        TODO: this class should live alongside library definitions and not here.
    """

    NAMESPACE: ClassVar[str] = "lib"

    @property
    def library_id(self) -> str:
        """The library identifier as used in Open edX (e.g., 'lib:DemoX:CSPROB').

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

    def exists(self) -> bool:
        """Check if the content library exists.

        Returns:
            bool: True if the content library exists, False otherwise.
        """
        try:
            library_key = LibraryLocatorV2.from_string(self.library_id)
            ContentLibrary.objects.get_by_key(library_key=library_key)
            return True
        except ContentLibrary.DoesNotExist:
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
        """Instantiate the appropriate SubjectData subclass dynamically.

        This metaclass enables polymorphic instantiation based on the namespaced_key prefix,
        automatically returning the correct subclass.

        Instantiation mode:
            - namespaced_key: Determines subclass from the namespace prefix before '^'.
              Example: SubjectData(namespaced_key='user^john_doe') → UserData

        Examples:
            >>> subject = SubjectData(namespaced_key='user^alice')
            >>> isinstance(subject, UserData)
            True
            >>> subject = SubjectData(namespaced_key='sub^generic')
            >>> isinstance(subject, SubjectData)
            True

        Note:
            Currently, we cannot instantiate by external_key alone because we don't have
            a way to determine the subclass from the external_key format. Use the specific
            subclass directly (e.g., UserData(external_key='alice')) when needed.
        """
        if cls is SubjectData and "namespaced_key" in kwargs:
            subject_cls = cls.get_subclass_by_namespaced_key(kwargs["namespaced_key"])
            return super(SubjectMeta, subject_cls).__call__(*args, **kwargs)

        return super().__call__(*args, **kwargs)

    @classmethod
    def get_subclass_by_namespaced_key(mcs, namespaced_key: str) -> Type["SubjectData"]:
        """Get the appropriate SubjectData subclass from the namespaced key.

        Extracts the namespace prefix (before '^') and returns the registered subclass.

        Args:
            namespaced_key: The namespaced key (e.g., 'user^alice', 'sub^generic').

        Returns:
            The SubjectData subclass for the namespace, or SubjectData if namespace not recognized.

        Examples:
            >>> SubjectMeta.get_subclass_by_namespaced_key('user^alice')
            <class 'UserData'>
            >>> SubjectMeta.get_subclass_by_namespaced_key('sub^generic')
            <class 'SubjectData'>
        """
        namespace = namespaced_key.split(AUTHZ_POLICY_ATTRIBUTES_SEPARATOR, 1)[0]
        return mcs.subject_registry.get(namespace, SubjectData)


@define
class SubjectData(AuthZData, metaclass=SubjectMeta):
    """A subject is an entity that can be assigned roles and permissions.

    This is the base class for subject types. Specific subject types (like UserData)
    are subclasses with their own namespace prefixes.

    Attributes:
        NAMESPACE: 'sub' for generic subjects.
        external_key: The subject identifier without namespace (e.g., 'generic').
        namespaced_key: The subject identifier with namespace (e.g., 'sub^generic').

    Examples:
        >>> subject = SubjectData(external_key='generic')
        >>> subject.namespaced_key
        'sub^generic'
    """

    NAMESPACE: ClassVar[str] = "sub"


@define
class UserData(SubjectData):
    """A user subject for authorization in the Open edX platform.

    This class represents individual users who can be assigned roles and permissions.
    Can be initialized with either external_key or namespaced_key parameter.

    Attributes:
        NAMESPACE: 'user' for user subjects.
        external_key: The username (e.g., 'john_doe').
        namespaced_key: The username with namespace prefix (e.g., 'user^john_doe').
        username: Property alias for external_key.

    Examples:
        >>> user = UserData(external_key='john_doe')
        >>> user.namespaced_key
        'user^john_doe'
        >>> user.username
        'john_doe'
        >>> user2 = UserData(namespaced_key='user^jane_smith')
        >>> user2.username
        'jane_smith'
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
    """An action represents an operation that can be performed in the authorization system.

    Actions are the operations that can be allowed or denied in authorization policies.

    Attributes:
        NAMESPACE: 'act' for actions.
        external_key: The action identifier (e.g., 'read', 'write', 'delete_library').
        namespaced_key: The action identifier with namespace (e.g., 'act^read', 'act^delete_library').
        name: Property that returns a human-readable action name (e.g., 'Read', 'Delete Library').

    Examples:
        >>> action = ActionData(external_key='delete_library')
        >>> action.namespaced_key
        'act^delete_library'
        >>> action.name
        'Delete Library'
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
    """A permission combines an action with an effect (allow or deny).

    Permissions define whether a specific action should be allowed or denied.
    They are typically associated with roles in the authorization system.

    Attributes:
        action: The action being permitted or denied (ActionData instance).
        effect: The effect of the permission, either 'allow' or 'deny' (default: 'allow').

    Examples:
        >>> read_action = ActionData(external_key='read')
        >>> permission = PermissionData(action=read_action, effect='allow')
        >>> str(permission)
        'Read - allow'
        >>> write_action = ActionData(external_key='write')
        >>> deny_perm = PermissionData(action=write_action, effect='deny')
        >>> str(deny_perm)
        'Write - deny'
    """

    action: ActionData = None
    effect: Literal["allow", "deny"] = "allow"

    @property
    def identifier(self) -> str:
        """Get the permission identifier.

        Returns:
            str: The permission identifier (e.g., 'delete_library').
        """
        return self.action.external_key

    def __str__(self):
        """Human readable string representation of the permission and its effect."""
        return f"{self.action} - {self.effect}"

    def __repr__(self):
        """Developer friendly string representation of the permission."""
        return f"{self.action.namespaced_key} => {self.effect}"


@define(eq=False)
class RoleData(AuthZData):
    """A role is a named collection of permissions that can be assigned to subjects.

    Roles group related permissions together for easier authorization management.

    Attributes:
        NAMESPACE: 'role' for roles.
        external_key: The role identifier (e.g., 'instructor', 'library_admin').
        namespaced_key: The role identifier with namespace (e.g., 'role^instructor').
        permissions: A list of PermissionData instances associated with this role.
        name: Property that returns a human-readable role name (e.g., 'Instructor', 'Library Admin').

    Examples:
        >>> role = RoleData(external_key='instructor')
        >>> role.namespaced_key
        'role^instructor'
        >>> role.name
        'Instructor'
        >>> action = ActionData(external_key='read')
        >>> perm = PermissionData(action=action, effect='allow')
        >>> role_with_perms = RoleData(external_key='instructor', permissions=[perm])
        >>> str(role_with_perms)
        'Instructor: Read - allow'
    """

    NAMESPACE: ClassVar[str] = "role"
    permissions: list[PermissionData] = []

    def __eq__(self, other):
        """Compare roles based on their namespaced_key."""
        if not isinstance(other, RoleData):
            return False
        return self.namespaced_key == other.namespaced_key

    @property
    def name(self) -> str:
        """The human-readable name of the role (e.g., 'Library Admin', 'Course Instructor').

        This property transforms the external_key into a human-readable display name
        by replacing underscores with spaces and capitalizing each word.

        Returns:
            str: The human-readable role name (e.g., 'Library Admin').
        """
        return self.external_key.replace("_", " ").title()

    def get_permission_identifiers(self) -> list[str]:
        """Get the technical identifiers for all permissions in this role.

        Returns:
            list[str]: Permission identifiers (e.g., ['delete_library', 'edit_content']).
        """
        return [permission.identifier for permission in self.permissions]

    def __str__(self):
        """Human readable string representation of the role and its permissions."""
        return f"{self.name}: {', '.join(str(p) for p in self.permissions)}"

    def __repr__(self):
        """Developer friendly string representation of the role."""
        return self.namespaced_key


@define
class RoleAssignmentData:
    """A role assignment links a subject, roles, and a scope together.

    Role assignments represent the authorization grants in the system. They specify
    that a particular subject (e.g., a user) has certain roles within a specific scope
    (e.g., a content library).

    Attributes:
        subject: The subject (e.g., UserData) to whom roles are assigned.
        roles: A list of RoleData instances being assigned to the subject.
        scope: The scope (e.g., ContentLibraryData) in which the roles apply.

    Examples:
        >>> user = UserData(external_key='john_doe')
        >>> role = RoleData(external_key='instructor')
        >>> library = ContentLibraryData(external_key='lib:DemoX:CSPROB')
        >>> assignment = RoleAssignmentData(subject=user, roles=[role], scope=library)
        >>> str(assignment)
        'john_doe => Instructor @ lib:DemoX:CSPROB'
        >>> repr(assignment)
        'user^john_doe => [role^instructor] @ lib^lib:DemoX:CSPROB'
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
