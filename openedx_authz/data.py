"""
Top-level data classes for actions and permissions.

These are defined here (rather than in openedx_authz.api.data) to avoid a
circular import between openedx_authz.api.data and openedx_authz.constants.permissions.
"""

from typing import ClassVar, Literal

from attrs import define

AUTHZ_POLICY_ATTRIBUTES_SEPARATOR = "^"


class AuthzBaseClass:
    """Base class for all authz classes."""

    SEPARATOR: ClassVar[str] = AUTHZ_POLICY_ATTRIBUTES_SEPARATOR
    NAMESPACE: ClassVar[str] = None


@define
class AuthZData(AuthzBaseClass):
    """Base class for all authz data classes."""

    external_key: str = ""
    namespaced_key: str = ""

    def __attrs_post_init__(self):
        """Derive namespaced_key from external_key or vice versa after initialization."""
        if not self.NAMESPACE:
            return

        if not self.external_key and not self.namespaced_key:
            raise ValueError("Either external_key or namespaced_key must be provided.")

        if not self.namespaced_key:
            self.namespaced_key = f"{self.NAMESPACE}{self.SEPARATOR}{self.external_key}"

        if not self.external_key:
            self.external_key = self.namespaced_key.split(self.SEPARATOR, 1)[1]


@define
class ActionData(AuthZData):
    """
    An action represents an operation that can be performed in the authorization system.

    Attributes:
        NAMESPACE: 'act' for actions.
        external_key: The action identifier (e.g., 'content_libraries.view_library').
        namespaced_key: The action identifier with namespace (e.g., 'act^content_libraries.view_library').

    Examples:
        >>> action = ActionData(external_key='content_libraries.delete_library')
        >>> action.namespaced_key
        'act^content_libraries.delete_library'
        >>> action.name
        'Content Libraries > Delete Library'
    """

    NAMESPACE: ClassVar[str] = "act"

    @property
    def name(self) -> str:
        """The human-readable name of the action (e.g., 'Content Libraries > Delete Library')."""
        parts = self.external_key.split(".")
        return " > ".join(part.replace("_", " ").title() for part in parts)

    def __str__(self):
        """Human readable string representation of the action."""
        return self.name

    def __repr__(self):
        """Developer friendly string representation of the action."""
        return self.namespaced_key


@define
class PermissionData:
    """
    A permission combines an action with an effect (allow or deny).

    Attributes:
        action: The action being permitted or denied (ActionData instance).
        effect: The effect of the permission, either 'allow' or 'deny' (default: 'allow').

    Examples:
        >>> read_action = ActionData(external_key='read')
        >>> permission = PermissionData(action=read_action, effect='allow')
        >>> str(permission)
        'Read - allow'
    """

    action: ActionData = None
    effect: Literal["allow", "deny"] = "allow"

    @property
    def identifier(self) -> str:
        """Get the permission identifier."""
        return self.action.external_key

    def __eq__(self, other: "PermissionData") -> bool:
        """Compare permissions based on their action identifier and effect."""
        if self.action is None or other.action is None:
            return False
        return self.action.external_key == other.action.external_key and self.effect == other.effect

    def __str__(self):
        """Human readable string representation of the permission and its effect."""
        return f"{self.action} - {self.effect}"

    def __repr__(self):
        """Developer friendly string representation of the permission."""
        return f"{self.action.namespaced_key} => {self.effect}"
