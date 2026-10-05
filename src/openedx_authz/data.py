"""
Top-level data classes for actions and permissions.

These are defined here (rather than in openedx_authz.api.data) to avoid a
circular import between openedx_authz.api.data and openedx_authz.constants.permissions.
"""

from enum import Enum
from typing import ClassVar, Literal

from attrs import define

AUTHZ_POLICY_ATTRIBUTES_SEPARATOR = "^"

# Shared authz vocabulary. These are the single source of truth for the namespace
# prefixes, scope wildcard, policy type, and default effect used across the authz
# data classes and the engine renderer, so every producer and consumer of a Casbin
# row agrees on its exact shape.
ROLE_NAMESPACE = "role"
ACTION_NAMESPACE = "act"
SCOPE_WILDCARD = "*"
POLICY_PTYPE = "p"
EFFECT_ALLOW = "allow"


class PolicyIndex(Enum):
    """
    Index positions for fields in a Casbin policy (p).

    Policies define permissions by linking roles to actions within scopes with an effect.
    Format: [role, action, scope, effect, ...]

    This is the single source of truth for the ``p`` row field layout, shared by
    every producer and consumer of a Casbin row (the engine renderer and the
    ``api`` data classes) so the mapping stays in one place.

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

    @classmethod
    def required_width(cls) -> int:
        """Return the number of leading fields that make up a complete ``p`` row (4)."""
        return len(cls)

    @classmethod
    def pad(cls, values: list[str]) -> list[str]:
        """
        Pad ``values`` with empty strings up to :meth:`required_width`.

        Callers that accept partially populated rows (e.g. the renderer
        round-tripping an in-memory row) pad first so the shared, strict
        :meth:`parse` does not reject them.
        """
        return list(values) + [""] * (cls.required_width() - len(values))

    @classmethod
    def parse(cls, policy: list[str]) -> tuple[str, str, str, str]:
        """
        Return ``(role, action, scope, effect)`` from a Casbin ``p`` row.

        The single place a ``p`` row is split into its fields, so every consumer
        agrees on both the layout and the minimum shape. Rows shorter than
        :meth:`required_width` are rejected; a caller that wants to tolerate a
        partial row should :meth:`pad` it first.

        Raises:
            ValueError: If ``policy`` has fewer than :meth:`required_width`
                elements.
        """
        if len(policy) < cls.required_width():
            raise ValueError(f"Invalid policy format. Expected at least {cls.required_width()} elements.")
        return (
            policy[cls.ROLE.value],
            policy[cls.ACT.value],
            policy[cls.SCOPE.value],
            policy[cls.EFFECT.value],
        )


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

    NAMESPACE: ClassVar[str] = ACTION_NAMESPACE

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
    effect: Literal["allow", "deny"] = EFFECT_ALLOW

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
